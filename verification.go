package secondfactor

import (
	"context"
	"github.com/jackc/pgx/v5"
	"time"
)

func (s *Service) VerifyTOTP(ctx context.Context, in Mutation) (Verification, error) {
	var out Verification
	e := s.run(ctx, in, "verify_totp", false, false, func(tx pgx.Tx, f *factor, v Session) error {
		i := in.Identity
		if len(f.secret) == 0 {
			return ErrInvalidCode
		}
		secret, e := s.open(i.Application, i.Subject, "factor", f.secret)
		if e != nil {
			return e
		}
		step, ok := matchStep(string(secret), in.Code, time.Now(), f.last)
		if !ok {
			return ErrInvalidCode
		}
		if _, e = tx.Exec(ctx, `UPDATE secondfactor_factors SET last_verified_time_step=$3,failures=0,blocked_until=NULL WHERE app_id=$1 AND subject=$2 AND last_verified_time_step<$3`, i.Application, i.Subject, step); e != nil {
			return e
		}
		out.Access, e = issue(ctx, tx, i, f.version, v, AccessProof)
		if e != nil {
			return e
		}
		out.Sensitive, e = issue(ctx, tx, i, f.version, v, SensitiveProof)
		return e
	})
	if e != nil {
		return Verification{}, e
	}
	return out, nil
}
func (s *Service) VerifyRecoveryCode(ctx context.Context, in Mutation) (Proof, error) {
	var out Proof
	e := s.run(ctx, in, "verify_recovery", false, false, func(tx pgx.Tx, f *factor, v Session) error {
		i := in.Identity
		c, ok := normalizeRecovery(in.Code)
		if !ok || len(f.secret) == 0 {
			return ErrInvalidCode
		}
		tag, e := tx.Exec(ctx, `DELETE FROM secondfactor_recovery_codes WHERE app_id=$1 AND subject=$2 AND code_hash=$3`, i.Application, i.Subject, hash(c))
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrInvalidCode
		}
		if _, e = tx.Exec(ctx, `UPDATE secondfactor_factors SET version=version+1,recovery_pending=true WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject); e != nil {
			return e
		}
		if e = invalidate(ctx, tx, i); e != nil {
			return e
		}
		if e = clearGrants(ctx, tx, i); e != nil {
			return e
		}
		out, e = grant(ctx, tx, i, f.version+1, v, nil)
		if e != nil {
			return e
		}
		return s.event(ctx, tx, i, "recovery_code_used", nil, nil)
	})
	if e != nil {
		return Proof{}, e
	}
	return out, nil
}
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, in Mutation) ([]string, error) {
	var out []string
	e := s.run(ctx, in, "regenerate", true, false, func(tx pgx.Tx, f *factor, v Session) error {
		i := in.Identity
		if e := checkProof(ctx, tx, i, in.Proof, SensitiveProof, f.version, v.Generation); e != nil {
			return e
		}
		var e error
		out, e = replaceCodes(ctx, tx, i)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE secondfactor_factors SET version=version+1 WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject); e != nil {
			return e
		}
		if e = invalidate(ctx, tx, i); e != nil {
			return e
		}
		if e = clearGrants(ctx, tx, i); e != nil {
			return e
		}
		return s.event(ctx, tx, i, "recovery_codes_regenerated", nil, nil)
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
