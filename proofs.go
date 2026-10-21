package secondfactor

import (
	"context"
	"github.com/jackc/pgx/v5"
	"time"
)

type ProofPurpose string

const (
	AccessProof      ProofPurpose = "access"
	SensitiveProof   ProofPurpose = "sensitive"
	ReplacementProof ProofPurpose = "replacement"
)

type Proof struct {
	Token     string       `json:"token"`
	Purpose   ProofPurpose `json:"purpose"`
	ExpiresAt time.Time    `json:"expires_at"`
}
type Verification struct {
	Access    Proof `json:"access"`
	Sensitive Proof `json:"sensitive"`
}

func issue(ctx context.Context, tx pgx.Tx, i Identity, v int64, session Session, purpose ProofPurpose) (Proof, error) {
	t, e := token()
	if e != nil {
		return Proof{}, e
	}
	ttl := 12 * time.Hour
	if purpose != AccessProof {
		ttl = 10 * time.Minute
	}
	p := Proof{t, purpose, minTime(time.Now().Add(ttl), session.ExpiresAt)}
	_, e = tx.Exec(ctx, `INSERT INTO secondfactor_proofs(app_id,token_hash,subject,session_id,version,generation,purpose,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, i.Application, hash(t), i.Subject, i.Session, v, session.Generation, string(purpose), p.ExpiresAt)
	return p, e
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func checkProof(ctx context.Context, tx pgx.Tx, i Identity, p string, purpose ProofPurpose, version, generation int64) error {
	if len(p) != 43 {
		return ErrDenied
	}
	var ok bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM secondfactor_proofs WHERE app_id=$1 AND subject=$2 AND session_id=$3 AND token_hash=$4 AND purpose=$5 AND version=$6 AND generation=$7 AND expires_at>clock_timestamp())`, i.Application, i.Subject, i.Session, hash(p), string(purpose), version, generation).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return ErrDenied
	}
	return nil
}
func checkGrant(ctx context.Context, tx pgx.Tx, i Identity, p string, version, generation int64) error {
	if len(p) != 43 {
		return ErrDenied
	}
	var ok bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM secondfactor_recovery_grants WHERE app_id=$1 AND subject=$2 AND session_id=$3 AND token_hash=$4 AND version=$5 AND generation=$6 AND expires_at>clock_timestamp())`, i.Application, i.Subject, i.Session, hash(p), version, generation).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return ErrDenied
	}
	return nil
}
func grant(ctx context.Context, tx pgx.Tx, i Identity, v int64, session Session, job *string) (Proof, error) {
	t, e := token()
	if e != nil {
		return Proof{}, e
	}
	p := Proof{t, ReplacementProof, minTime(time.Now().Add(10*time.Minute), session.ExpiresAt)}
	_, e = tx.Exec(ctx, `INSERT INTO secondfactor_recovery_grants(app_id,token_hash,subject,session_id,version,generation,expires_at,job_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, i.Application, hash(t), i.Subject, i.Session, v, session.Generation, p.ExpiresAt, job)
	return p, e
}
func (s *Service) ValidateProof(ctx context.Context, i Identity, p string, purpose ProofPurpose) error {
	if purpose != AccessProof && purpose != SensitiveProof {
		return ErrDenied
	}
	session, e := s.session(ctx, i)
	if e != nil {
		return e
	}
	return s.transact(ctx, Mutation{Identity: i}, "validate", false, false, session, func(tx pgx.Tx, f *factor, v Session) error {
		return checkProof(ctx, tx, i, p, purpose, f.version, v.Generation)
	})
}

// RevokeSession invalidates every proof and replacement grant issued for this primary session.
func (s *Service) RevokeSession(ctx context.Context, in Mutation) error {
	return s.run(ctx, in, "session_revoke", true, true, func(tx pgx.Tx, f *factor, v Session) error {
		for _, table := range []string{"secondfactor_proofs", "secondfactor_recovery_grants"} {
			if _, e := tx.Exec(ctx, "DELETE FROM "+table+" WHERE app_id=$1 AND subject=$2 AND session_id=$3", in.Identity.Application, in.Identity.Subject, in.Identity.Session); e != nil {
				return e
			}
		}
		return nil
	})
}
