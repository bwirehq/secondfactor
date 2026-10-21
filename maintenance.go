package secondfactor

import (
	"context"
	"encoding/json"
)

// ReencryptBatch rotates encrypted fields without changing factor/proof versions.
// The operator repeats until zero and checks KeyUsage before removing an old key.
func (s *Service) ReencryptBatch(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 100 {
		return 0, ErrInvalidInput
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return 0, e
	}
	defer rollback(tx)
	n := 0
	for _, spec := range []struct{ table, column, id, purpose string }{{"secondfactor_factors", "secret", "subject", "factor"}, {"secondfactor_enrollments", "secret", "subject", "pending"}, {"secondfactor_events", "encrypted_payload", "event_id", "recovery_delivery"}} {
		rows, e := tx.Query(ctx, "SELECT app_id,subject,"+spec.id+","+spec.column+" FROM "+spec.table+" WHERE "+spec.column+" IS NOT NULL AND convert_from("+spec.column+",'UTF8')::jsonb->>'key' <> $1 ORDER BY app_id,"+spec.id+" LIMIT $2 FOR UPDATE SKIP LOCKED", s.active, limit-n)
		if e != nil {
			return n, e
		}
		type item struct {
			app, sub, id string
			raw          []byte
		}
		var items []item
		for rows.Next() {
			var v item
			if e = rows.Scan(&v.app, &v.sub, &v.id, &v.raw); e != nil {
				rows.Close()
				return n, e
			}
			items = append(items, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return n, e
		}
		for _, v := range items {
			plain, e := s.open(v.app, v.sub, spec.purpose, v.raw)
			if e != nil {
				return n, e
			}
			var env sealed
			if json.Unmarshal(v.raw, &env) != nil {
				return n, ErrUnavailable
			}
			raw, e := s.seal(v.app, v.sub, spec.purpose, env.Version, plain)
			if e != nil {
				return n, e
			}
			if _, e = tx.Exec(ctx, "UPDATE "+spec.table+" SET "+spec.column+"=$3 WHERE app_id=$1 AND "+spec.id+"=$2", v.app, v.id, raw); e != nil {
				return n, e
			}
			n++
		}
		if n >= limit {
			break
		}
	}
	return n, tx.Commit(ctx)
}
func (s *Service) KeyUsage(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	for _, v := range []struct{ t, c string }{{"secondfactor_factors", "secret"}, {"secondfactor_enrollments", "secret"}, {"secondfactor_events", "encrypted_payload"}} {
		rows, e := s.pool.Query(ctx, "SELECT convert_from("+v.c+",'UTF8')::jsonb->>'key',count(*) FROM "+v.t+" WHERE "+v.c+" IS NOT NULL GROUP BY 1")
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var k string
			var n int
			if e = rows.Scan(&k, &n); e != nil {
				rows.Close()
				return nil, e
			}
			out[k] += n
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (s *Service) CheckKeyCoverage(ctx context.Context) error {
	usage, e := s.KeyUsage(ctx)
	if e != nil {
		return e
	}
	for k, n := range usage {
		if n > 0 && len(s.keys[k]) != 32 {
			return ErrUnavailable
		}
	}
	return nil
}

// Cleanup is explicit and bounded. Unfinished recovery jobs and their audit records are retained.
func (s *Service) Cleanup(ctx context.Context) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer rollback(tx)
	for _, q := range []string{
		`DELETE FROM secondfactor_assertion_replays WHERE ctid IN (SELECT ctid FROM secondfactor_assertion_replays WHERE expires_at<clock_timestamp() LIMIT 1000)`,
		`DELETE FROM secondfactor_idempotency WHERE ctid IN (SELECT ctid FROM secondfactor_idempotency WHERE expires_at<clock_timestamp() LIMIT 1000)`,
		`DELETE FROM secondfactor_rate_limits WHERE ctid IN (SELECT ctid FROM secondfactor_rate_limits WHERE expires_at<clock_timestamp() LIMIT 1000)`,
		`DELETE FROM secondfactor_proofs WHERE ctid IN (SELECT ctid FROM secondfactor_proofs WHERE expires_at<clock_timestamp() LIMIT 1000)`,
		`DELETE FROM secondfactor_enrollments WHERE ctid IN (SELECT ctid FROM secondfactor_enrollments WHERE expires_at<clock_timestamp() LIMIT 1000)`,
		`DELETE FROM secondfactor_recovery_grants WHERE ctid IN (SELECT ctid FROM secondfactor_recovery_grants WHERE expires_at<clock_timestamp() LIMIT 1000)`,
		`UPDATE secondfactor_events SET encrypted_payload=NULL WHERE ctid IN (SELECT ctid FROM secondfactor_events WHERE encrypted_payload IS NOT NULL AND kind='recovery_invitation' AND created_at<clock_timestamp()-interval '10 minutes' LIMIT 1000)`,
		`DELETE FROM secondfactor_events WHERE ctid IN (SELECT e.ctid FROM secondfactor_events e WHERE e.created_at<clock_timestamp()-interval '90 days' AND e.acknowledged_at<clock_timestamp()-interval '30 days' AND NOT EXISTS(SELECT 1 FROM secondfactor_assisted_recoveries r WHERE r.app_id=e.app_id AND r.subject=e.subject AND r.state NOT IN('completed','cancelled')) LIMIT 1000)`,
	} {
		if _, e = tx.Exec(ctx, q); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
