package secondfactor

import (
	"context"
	"encoding/json"
	"time"
)

type Event struct {
	ID        string          `json:"id"`
	Subject   string          `json:"subject"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	Delivery  json.RawMessage `json:"delivery,omitempty"`
	Lease     string          `json:"lease"`
	CreatedAt time.Time       `json:"created_at"`
}

// ClaimEvents is privileged application-backend delivery access, not an end-user API.
// Delivery can contain a recovery invitation. Consumers must not log or expose it.
func (s *Service) ClaimEvents(ctx context.Context, application string, limit int) ([]Event, error) {
	if _, ok := s.apps[application]; !ok || limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rollback(tx)
	rows, e := tx.Query(ctx, `SELECT event_id,subject,kind,payload,encrypted_payload,created_at FROM secondfactor_events WHERE app_id=$1 AND acknowledged_at IS NULL AND (lease_until IS NULL OR lease_until<=clock_timestamp()) ORDER BY created_at,event_id LIMIT $2 FOR UPDATE SKIP LOCKED`, application, limit)
	if e != nil {
		return nil, ErrUnavailable
	}
	type pending struct {
		event Event
		raw   []byte
	}
	var items []pending
	for rows.Next() {
		var p pending
		if e = rows.Scan(&p.event.ID, &p.event.Subject, &p.event.Kind, &p.event.Payload, &p.raw, &p.event.CreatedAt); e != nil {
			rows.Close()
			return nil, ErrUnavailable
		}
		items = append(items, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, ErrUnavailable
	}
	out := make([]Event, 0, len(items))
	for _, p := range items {
		if len(p.raw) > 0 {
			var active bool
			e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM secondfactor_assisted_recoveries WHERE app_id=$1 AND subject=$2 AND job_id=$3 AND state='invited' AND expires_at>clock_timestamp())`, application, p.event.Subject, stringField(p.event.Payload, "job_id")).Scan(&active)
			if e != nil {
				return nil, ErrUnavailable
			}
			if active {
				raw, e := s.open(application, p.event.Subject, "recovery_delivery", p.raw)
				if e != nil {
					return nil, ErrUnavailable
				}
				p.event.Delivery = raw
			}
		}
		lease, e := token()
		if e != nil {
			return nil, ErrUnavailable
		}
		p.event.Lease = lease
		if _, e = tx.Exec(ctx, `UPDATE secondfactor_events SET lease_hash=$3,lease_until=clock_timestamp()+interval '30 seconds',attempts=attempts+1 WHERE app_id=$1 AND event_id=$2`, application, p.event.ID, hash(lease)); e != nil {
			return nil, ErrUnavailable
		}
		out = append(out, p.event)
	}
	if tx.Commit(ctx) != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
func stringField(raw []byte, key string) string {
	var v map[string]string
	_ = json.Unmarshal(raw, &v)
	return v[key]
}
func (s *Service) AckEvent(ctx context.Context, app, id, lease string) error {
	if len(lease) != 43 {
		return ErrDenied
	}
	tag, e := s.pool.Exec(ctx, `UPDATE secondfactor_events SET acknowledged_at=clock_timestamp(),encrypted_payload=NULL,lease_hash=NULL,lease_until=NULL WHERE app_id=$1 AND event_id=$2 AND lease_hash=$3 AND lease_until>clock_timestamp() AND acknowledged_at IS NULL`, app, id, hash(lease))
	if e != nil {
		return ErrUnavailable
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
