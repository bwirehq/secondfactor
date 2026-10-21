package secondfactor

import (
	"context"
	"github.com/jackc/pgx/v5"
)

type Status struct {
	Enrolled               bool  `json:"enrolled"`
	RecoveryPending        bool  `json:"recovery_pending"`
	RemainingRecoveryCodes int   `json:"remaining_recovery_codes"`
	Version                int64 `json:"version"`
}

func (s *Service) Status(ctx context.Context, i Identity) (Status, error) {
	var out Status
	session, e := s.session(ctx, i)
	if e != nil {
		return out, e
	}
	e = s.transact(ctx, Mutation{Identity: i}, "status", false, true, session, func(tx pgx.Tx, f *factor, v Session) error {
		out = Status{Enrolled: len(f.secret) > 0, RecoveryPending: f.pending, Version: f.version}
		return tx.QueryRow(ctx, `SELECT count(*) FROM secondfactor_recovery_codes WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject).Scan(&out.RemainingRecoveryCodes)
	})
	return out, e
}
func (s *Service) RevokeFactor(ctx context.Context, in Mutation) error {
	return s.run(ctx, in, "revoke", true, false, func(tx pgx.Tx, f *factor, v Session) error {
		i := in.Identity
		if e := checkProof(ctx, tx, i, in.Proof, SensitiveProof, f.version, v.Generation); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE secondfactor_factors SET secret=NULL,version=version+1,last_verified_time_step=-1 WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject); e != nil {
			return e
		}
		for _, table := range []string{"secondfactor_proofs", "secondfactor_recovery_grants", "secondfactor_enrollments", "secondfactor_recovery_codes"} {
			if _, e := tx.Exec(ctx, "DELETE FROM "+table+" WHERE app_id=$1 AND subject=$2", i.Application, i.Subject); e != nil {
				return e
			}
		}
		return s.event(ctx, tx, i, "disabled", nil, nil)
	})
}
