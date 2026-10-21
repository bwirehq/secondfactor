package secondfactor

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"time"
)

type RecoveryJob struct {
	JobID string `json:"job_id"`
	State string `json:"state"`
}

func (s *Service) authorize(ctx context.Context, in Mutation, action string) (RecoveryAuthorization, error) {
	if !validText(in.Target) || !validID(in.JobID) || len(in.Reason) < 10 || len(in.Reason) > 500 || !validText(in.Evidence) {
		return RecoveryAuthorization{}, ErrInvalidInput
	}
	if _, e := s.session(ctx, in.Identity); e != nil {
		return RecoveryAuthorization{}, e
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	v, e := s.recovery.AuthorizeRecovery(c, RecoveryRequest{Action: action, Actor: in.Identity, Target: in.Target, Reason: in.Reason, Evidence: in.Evidence, JobID: in.JobID})
	if e != nil {
		return v, ErrUnavailable
	}
	if !v.Allowed || !validText(v.DecisionID) || v.TargetGeneration < 0 {
		return v, ErrDenied
	}
	return v, nil
}
func (s *Service) StartAssistedRecovery(ctx context.Context, in Mutation) (RecoveryJob, error) {
	if len(in.IdempotencyKey) < 16 || len(in.IdempotencyKey) > 128 {
		return RecoveryJob{}, invalid("idempotency key")
	}
	if e := s.admission(ctx, in.Identity, "recovery_start"); e != nil {
		return RecoveryJob{}, e
	}
	a, e := s.authorize(ctx, in, "start")
	if e != nil {
		return RecoveryJob{}, e
	}
	actor := in.Identity
	target := actor
	target.Subject = in.Target
	if e = s.admission(ctx, target, "recovery_start"); e != nil {
		return RecoveryJob{}, e
	}
	in.Identity = target
	e = s.transact(ctx, in, "recovery_start", true, true, Session{}, func(tx pgx.Tx, f *factor, v Session) error {
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM secondfactor_assisted_recoveries WHERE app_id=$1 AND subject=$2 AND state NOT IN('completed','cancelled'))`, target.Application, target.Subject).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return ErrConflict
		}
		if _, e := tx.Exec(ctx, `INSERT INTO secondfactor_assisted_recoveries(app_id,job_id,subject,actor,reason,decision_id,state,pre_generation) VALUES($1,$2,$3,$4,$5,$6,'blocked',$7)`, target.Application, in.JobID, target.Subject, actor.Subject, in.Reason, a.DecisionID, a.TargetGeneration); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE secondfactor_factors SET recovery_pending=true,version=version+1 WHERE app_id=$1 AND subject=$2`, target.Application, target.Subject); e != nil {
			return e
		}
		if e := invalidate(ctx, tx, target); e != nil {
			return e
		}
		if e := clearGrants(ctx, tx, target); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM secondfactor_enrollments WHERE app_id=$1 AND subject=$2`, target.Application, target.Subject); e != nil {
			return e
		}
		if e := s.event(ctx, tx, target, "recovery_started", map[string]string{"job_id": in.JobID, "actor": actor.Subject, "reason": in.Reason, "decision_id": a.DecisionID}, nil); e != nil {
			return e
		}
		return s.event(ctx, tx, target, "session_revocation_required", map[string]string{"job_id": in.JobID}, nil)
	})
	if e != nil {
		return RecoveryJob{}, e
	}
	in.Identity = actor
	return s.ResumeAssistedRecovery(ctx, in)
}

// ResumeAssistedRecovery retries the same independently authorized, durable revocation job.
func (s *Service) ResumeAssistedRecovery(ctx context.Context, in Mutation) (RecoveryJob, error) {
	if e := s.admission(ctx, in.Identity, "recovery_resume"); e != nil {
		return RecoveryJob{}, e
	}
	if _, e := s.authorize(ctx, in, "resume"); e != nil {
		return RecoveryJob{}, e
	}
	var pre int64
	var state string
	e := s.pool.QueryRow(ctx, `SELECT pre_generation,state FROM secondfactor_assisted_recoveries WHERE app_id=$1 AND subject=$2 AND job_id=$3`, in.Identity.Application, in.Target, in.JobID).Scan(&pre, &state)
	if e == pgx.ErrNoRows {
		return RecoveryJob{}, ErrDenied
	}
	if e != nil {
		return RecoveryJob{}, ErrUnavailable
	}
	if state != "blocked" {
		return RecoveryJob{in.JobID, state}, nil
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	rev, e := s.revoker.RevokeSessions(c, RevocationRequest{in.Identity.Application, in.Target, in.JobID, pre})
	cancel()
	if e != nil || !rev.Confirmed || rev.Generation <= pre {
		return RecoveryJob{}, ErrUnavailable
	}
	target := in.Identity
	target.Subject = in.Target
	in.Identity = target
	e = s.transact(ctx, in, "recovery_resume", false, true, Session{}, func(tx pgx.Tx, f *factor, v Session) error {
		var current string
		if e := tx.QueryRow(ctx, `SELECT state FROM secondfactor_assisted_recoveries WHERE app_id=$1 AND subject=$2 AND job_id=$3 FOR UPDATE`, target.Application, target.Subject, in.JobID).Scan(&current); e != nil {
			return e
		}
		state = current
		if current != "blocked" {
			return nil
		}
		invitation, e := token()
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(map[string]string{"invitation": invitation, "job_id": in.JobID})
		encrypted, e := s.seal(target.Application, target.Subject, "recovery_delivery", f.version, raw)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE secondfactor_assisted_recoveries SET state='invited',new_generation=$4,confirmed_at=clock_timestamp(),invitation_hash=$5,expires_at=clock_timestamp()+interval '10 minutes' WHERE app_id=$1 AND subject=$2 AND job_id=$3`, target.Application, target.Subject, in.JobID, rev.Generation, hash(invitation)); e != nil {
			return e
		}
		state = "invited"
		return s.event(ctx, tx, target, "recovery_invitation", map[string]string{"job_id": in.JobID}, encrypted)
	})
	if e != nil {
		return RecoveryJob{}, e
	}
	return RecoveryJob{in.JobID, state}, nil
}
func (s *Service) CompleteAssistedRecovery(ctx context.Context, in Mutation) (Proof, error) {
	var out Proof
	e := s.run(ctx, in, "recovery_complete", true, true, func(tx pgx.Tx, f *factor, v Session) error {
		i := in.Identity
		if !f.pending || len(in.Invitation) != 43 || !validID(in.JobID) {
			return ErrDenied
		}
		var generation int64
		var initiated time.Time
		e := tx.QueryRow(ctx, `SELECT new_generation,initiated_at FROM secondfactor_assisted_recoveries WHERE app_id=$1 AND subject=$2 AND job_id=$3 AND state='invited' AND invitation_hash=$4 AND expires_at>clock_timestamp() FOR UPDATE`, i.Application, i.Subject, in.JobID, hash(in.Invitation)).Scan(&generation, &initiated)
		if e == pgx.ErrNoRows {
			return ErrInvalidCode
		}
		if e != nil {
			return e
		}
		if v.Generation < generation || v.AuthenticatedAt.Before(initiated.Add(-5*time.Second)) {
			return ErrDenied
		}
		if _, e = tx.Exec(ctx, `UPDATE secondfactor_assisted_recoveries SET state='replacing',invitation_hash=NULL WHERE app_id=$1 AND job_id=$2`, i.Application, in.JobID); e != nil {
			return e
		}
		out, e = grant(ctx, tx, i, f.version, v, &in.JobID)
		return e
	})
	if e != nil {
		return Proof{}, e
	}
	return out, nil
}

// CancelAssistedRecovery requires independent authorization, invalidates all grants,
// and preserves the blocked factor. A separately authorized restart is required.
func (s *Service) CancelAssistedRecovery(ctx context.Context, in Mutation) error {
	if len(in.IdempotencyKey) < 16 || len(in.IdempotencyKey) > 128 {
		return ErrInvalidInput
	}
	if e := s.admission(ctx, in.Identity, "recovery_cancel"); e != nil {
		return e
	}
	if _, e := s.authorize(ctx, in, "cancel"); e != nil {
		return e
	}
	actor := in.Identity.Subject
	in.Identity.Subject = in.Target
	return s.transact(ctx, in, "recovery_cancel", true, true, Session{}, func(tx pgx.Tx, f *factor, v Session) error {
		i := in.Identity
		tag, e := tx.Exec(ctx, `UPDATE secondfactor_assisted_recoveries SET state='cancelled',invitation_hash=NULL WHERE app_id=$1 AND subject=$2 AND job_id=$3 AND state IN('invited','replacing')`, i.Application, i.Subject, in.JobID)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		if _, e = tx.Exec(ctx, `UPDATE secondfactor_factors SET version=version+1,recovery_pending=true WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject); e != nil {
			return e
		}
		for _, t := range []string{"secondfactor_recovery_grants", "secondfactor_proofs", "secondfactor_enrollments", "secondfactor_recovery_codes"} {
			if _, e = tx.Exec(ctx, "DELETE FROM "+t+" WHERE app_id=$1 AND subject=$2", i.Application, i.Subject); e != nil {
				return e
			}
		}
		return s.event(ctx, tx, i, "recovery_cancelled", map[string]string{"actor": actor, "reason": in.Reason}, nil)
	})
}
