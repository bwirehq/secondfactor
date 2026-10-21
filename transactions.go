package secondfactor

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

type Mutation struct {
	Identity       Identity `json:"-"`
	IdempotencyKey string   `json:"-"`
	Code           string   `json:"code,omitempty"`
	Proof          string   `json:"proof,omitempty"`
	AccountName    string   `json:"account_name,omitempty"`
	Target         string   `json:"target,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	JobID          string   `json:"job_id,omitempty"`
	Invitation     string   `json:"invitation,omitempty"`
}
type factor struct {
	secret        []byte
	version, last int64
	pending       bool
	failures      int
	since         time.Time
	blocked       *time.Time
}

func rollback(tx pgx.Tx) {
	ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
	defer c()
	_ = tx.Rollback(ctx)
}
func (s *Service) admission(ctx context.Context, i Identity, op string) error {
	if _, ok := s.apps[i.Application]; !ok || !validText(i.Subject) || !validText(i.Session) || !validText(i.Source) {
		return ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer rollback(tx)
	type bucket struct {
		k   string
		max int
	}
	bs := []bucket{{"app", s.limits.Application}, {"account:" + i.Subject, s.limits.Account}, {"session:" + i.Subject + ":" + i.Session, s.limits.Session}, {"source:" + i.Source, s.limits.Source}, {"operation:" + op + ":" + i.Subject, s.limits.Account}}
	if op == "begin" || op == "replace" || op == "recovery_start" {
		bs = append(bs, bucket{"sensitive:" + i.Subject, s.limits.Sensitive})
	}
	var wait time.Duration
	now := time.Now()
	for _, b := range bs {
		var n int
		var until time.Time
		e = tx.QueryRow(ctx, `INSERT INTO secondfactor_rate_limits(app_id,bucket,attempts,expires_at) VALUES($1,$2,1,$3) ON CONFLICT(app_id,bucket) DO UPDATE SET attempts=CASE WHEN secondfactor_rate_limits.expires_at<=clock_timestamp() THEN 1 ELSE secondfactor_rate_limits.attempts+1 END,expires_at=CASE WHEN secondfactor_rate_limits.expires_at<=clock_timestamp() THEN EXCLUDED.expires_at ELSE secondfactor_rate_limits.expires_at END RETURNING attempts,expires_at`, i.Application, hash(b.k), now.Add(s.limits.Window)).Scan(&n, &until)
		if e != nil {
			return ErrUnavailable
		}
		if n > b.max {
			wait = max(wait, until.Sub(now))
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return ErrUnavailable
	}
	if wait > 0 {
		return limited(wait)
	}
	return nil
}
func (s *Service) run(ctx context.Context, in Mutation, op string, idempotent bool, allowRecovery bool, fn func(pgx.Tx, *factor, Session) error) error {
	if idempotent && (len(in.IdempotencyKey) < 16 || len(in.IdempotencyKey) > 128) {
		return invalid("idempotency key")
	}
	if e := s.admission(ctx, in.Identity, op); e != nil {
		return e
	}
	session, e := s.session(ctx, in.Identity)
	if e != nil {
		return e
	}
	return s.transact(ctx, in, op, idempotent, allowRecovery, session, fn)
}
func (s *Service) transact(ctx context.Context, in Mutation, op string, idempotent bool, allowRecovery bool, session Session, fn func(pgx.Tx, *factor, Session) error) error {
	i := in.Identity
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); e != nil {
		return ErrUnavailable
	}
	if _, e = tx.Exec(ctx, `INSERT INTO secondfactor_factors(app_id,subject) VALUES($1,$2) ON CONFLICT DO NOTHING`, i.Application, i.Subject); e != nil {
		return ErrUnavailable
	}

	var f factor
	e = tx.QueryRow(ctx, `SELECT secret,version,last_verified_time_step,recovery_pending,failures,failures_since,blocked_until FROM secondfactor_factors WHERE app_id=$1 AND subject=$2 FOR UPDATE`, i.Application, i.Subject).Scan(&f.secret, &f.version, &f.last, &f.pending, &f.failures, &f.since, &f.blocked)
	if e != nil {
		return ErrUnavailable
	}
	if !session.ExpiresAt.IsZero() && !session.ExpiresAt.After(time.Now()) {
		return ErrDenied
	}
	// Serialize first, then examine idempotency, so concurrent retries cannot repeat a transition.
	raw, _ := json.Marshal(in)
	requestHash := hash(string(raw))
	if idempotent {
		var previous []byte
		var redacted bool
		e = tx.QueryRow(ctx, `SELECT request_hash,redacted FROM secondfactor_idempotency WHERE app_id=$1 AND subject=$2 AND session_id=$3 AND operation=$4 AND key_hash=$5 AND expires_at>clock_timestamp()`, i.Application, i.Subject, i.Session, op, hash(in.IdempotencyKey)).Scan(&previous, &redacted)
		if e == nil {
			if subtle.ConstantTimeCompare(previous, requestHash) != 1 {
				return ErrConflict
			}
			if redacted {
				return ErrSecretConsumed
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return ErrUnavailable
		}
	}
	if f.pending && !allowRecovery {
		return ErrRecoveryPending
	}
	if f.blocked != nil && f.blocked.After(time.Now()) {
		return limited(time.Until(*f.blocked))
	}
	e = fn(tx, &f, session)
	if errors.Is(e, ErrInvalidCode) {
		now := time.Now()
		if now.Sub(f.since) >= s.limits.Window {
			f.failures = 0
			f.since = now
		}
		f.failures++
		var blocked *time.Time
		if f.failures >= s.limits.Failures {
			t := now.Add(s.limits.Block)
			blocked = &t
		}
		if _, err := tx.Exec(ctx, `UPDATE secondfactor_factors SET failures=$3,failures_since=$4,blocked_until=$5 WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject, f.failures, f.since, blocked); err != nil {
			return ErrUnavailable
		}
		if f.failures == s.limits.Failures {
			if err := s.event(ctx, tx, i, "verification_failures", nil, nil); err != nil {
				return ErrUnavailable
			}
		}
		if tx.Commit(ctx) != nil {
			return ErrUnavailable
		}
		return ErrInvalidCode
	}
	if e != nil {
		var known *Error
		if errors.As(e, &known) {
			return e
		}
		return ErrUnavailable
	}
	if idempotent {
		redacted := op == "begin" || op == "replace" || op == "confirm" || op == "regenerate" || op == "recovery_complete"
		_, e = tx.Exec(ctx, `INSERT INTO secondfactor_idempotency(app_id,subject,session_id,operation,key_hash,request_hash,redacted,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '24 hours') ON CONFLICT(app_id,subject,session_id,operation,key_hash) DO UPDATE SET request_hash=EXCLUDED.request_hash,expires_at=EXCLUDED.expires_at,redacted=EXCLUDED.redacted`, i.Application, i.Subject, i.Session, op, hash(in.IdempotencyKey), requestHash, redacted)
		if e != nil {
			return ErrUnavailable
		}
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) event(ctx context.Context, tx pgx.Tx, i Identity, kind string, payload any, encrypted []byte) error {
	id, e := token()
	if e != nil {
		return e
	}
	if payload == nil {
		payload = map[string]string{}
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO secondfactor_events(app_id,event_id,subject,kind,payload,encrypted_payload) VALUES($1,$2,$3,$4,$5,$6)`, i.Application, id, i.Subject, kind, raw, encrypted)
	return e
}
func invalidate(ctx context.Context, tx pgx.Tx, i Identity) error {
	_, e := tx.Exec(ctx, `DELETE FROM secondfactor_proofs WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject)
	return e
}
func clearGrants(ctx context.Context, tx pgx.Tx, i Identity) error {
	_, e := tx.Exec(ctx, `DELETE FROM secondfactor_recovery_grants WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject)
	return e
}
