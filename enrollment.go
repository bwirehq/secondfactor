package secondfactor

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"time"
)

type Enrollment struct {
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Confirmation struct {
	RecoveryCodes []string     `json:"recovery_codes"`
	Verification  Verification `json:"verification"`
}

func (s *Service) BeginEnrollment(ctx context.Context, in Mutation) (Enrollment, error) {
	return s.begin(ctx, in, "begin")
}
func (s *Service) ReplaceFactor(ctx context.Context, in Mutation) (Enrollment, error) {
	return s.begin(ctx, in, "replace")
}
func (s *Service) begin(ctx context.Context, in Mutation, op string) (Enrollment, error) {
	var out Enrollment
	if !validText(in.AccountName) {
		return out, invalid("account name")
	}
	e := s.run(ctx, in, op, true, true, func(tx pgx.Tx, f *factor, v Session) error {
		i := in.Identity
		if len(f.secret) > 0 || f.pending {
			if f.pending {
				if e := checkGrant(ctx, tx, i, in.Proof, f.version, v.Generation); e != nil {
					return ErrRecoveryPending
				}
			} else if e := checkProof(ctx, tx, i, in.Proof, SensitiveProof, f.version, v.Generation); e != nil {
				if e = checkGrant(ctx, tx, i, in.Proof, f.version, v.Generation); e != nil {
					return e
				}
			}
		}
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM secondfactor_enrollments WHERE app_id=$1 AND subject=$2 AND expires_at>clock_timestamp())`, i.Application, i.Subject).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return ErrConflict
		}
		key, e := totp.Generate(totp.GenerateOpts{Issuer: s.apps[i.Application].Issuer, AccountName: in.AccountName, Period: 30, SecretSize: 20, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e != nil {
			return e
		}
		secret, e := s.seal(i.Application, i.Subject, "pending", f.version, []byte(key.Secret()))
		if e != nil {
			return e
		}
		out = Enrollment{key.Secret(), key.URL(), time.Now().Add(10 * time.Minute)}
		var gh []byte
		if len(in.Proof) > 0 {
			gh = hash(in.Proof)
		}
		_, e = tx.Exec(ctx, `INSERT INTO secondfactor_enrollments(app_id,subject,secret,session_id,expires_at,grant_hash) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(app_id,subject) DO UPDATE SET secret=EXCLUDED.secret,session_id=EXCLUDED.session_id,expires_at=EXCLUDED.expires_at,grant_hash=EXCLUDED.grant_hash`, i.Application, i.Subject, secret, i.Session, out.ExpiresAt, gh)
		return e
	})
	if e != nil {
		return Enrollment{}, e
	}
	return out, nil
}
func (s *Service) ConfirmEnrollment(ctx context.Context, in Mutation) (Confirmation, error) {
	var out Confirmation
	e := s.run(ctx, in, "confirm", true, true, func(tx pgx.Tx, f *factor, v Session) error {
		i := in.Identity
		if len(f.secret) > 0 || f.pending {
			if f.pending {
				if e := checkGrant(ctx, tx, i, in.Proof, f.version, v.Generation); e != nil {
					return e
				}
			} else if e := checkProof(ctx, tx, i, in.Proof, SensitiveProof, f.version, v.Generation); e != nil {
				if e = checkGrant(ctx, tx, i, in.Proof, f.version, v.Generation); e != nil {
					return e
				}
			}
		}
		var raw []byte
		e := tx.QueryRow(ctx, `SELECT secret FROM secondfactor_enrollments WHERE app_id=$1 AND subject=$2 AND session_id=$3 AND expires_at>clock_timestamp() AND (grant_hash IS NULL OR grant_hash=$4)`, i.Application, i.Subject, i.Session, hash(in.Proof)).Scan(&raw)
		if e == pgx.ErrNoRows {
			return ErrConflict
		}
		if e != nil {
			return e
		}
		secret, e := s.open(i.Application, i.Subject, "pending", raw)
		if e != nil {
			return e
		}
		step, ok := matchStep(string(secret), in.Code, time.Now(), -1)
		if !ok {
			return ErrInvalidCode
		}
		encrypted, e := s.seal(i.Application, i.Subject, "factor", f.version+1, secret)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE secondfactor_factors SET secret=$3,version=version+1,last_verified_time_step=$4,recovery_pending=false,failures=0,blocked_until=NULL WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject, encrypted, step); e != nil {
			return e
		}
		if e = invalidate(ctx, tx, i); e != nil {
			return e
		}
		if e = clearGrants(ctx, tx, i); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM secondfactor_enrollments WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject); e != nil {
			return e
		}
		out.RecoveryCodes, e = replaceCodes(ctx, tx, i)
		if e != nil {
			return e
		}
		out.Verification.Access, e = issue(ctx, tx, i, f.version+1, v, AccessProof)
		if e != nil {
			return e
		}
		out.Verification.Sensitive, e = issue(ctx, tx, i, f.version+1, v, SensitiveProof)
		if e != nil {
			return e
		}
		kind := "enabled"
		if len(f.secret) > 0 {
			kind = "authenticator_replaced"
		}
		if e = s.event(ctx, tx, i, kind, nil, nil); e != nil {
			return e
		}
		if f.pending {
			if _, e = tx.Exec(ctx, `UPDATE secondfactor_assisted_recoveries SET state='completed',invitation_hash=NULL WHERE app_id=$1 AND subject=$2 AND state='replacing'`, i.Application, i.Subject); e != nil {
				return e
			}
			return s.event(ctx, tx, i, "recovery_completed", nil, nil)
		}
		return nil
	})
	if e != nil {
		return Confirmation{}, e
	}
	return out, nil
}
func replaceCodes(ctx context.Context, tx pgx.Tx, i Identity) ([]string, error) {
	if _, e := tx.Exec(ctx, `DELETE FROM secondfactor_recovery_codes WHERE app_id=$1 AND subject=$2`, i.Application, i.Subject); e != nil {
		return nil, e
	}
	out := make([]string, 10)
	for n := range out {
		c, e := recoveryCode()
		if e != nil {
			return nil, e
		}
		normalized, _ := normalizeRecovery(c)
		if _, e = tx.Exec(ctx, `INSERT INTO secondfactor_recovery_codes(app_id,subject,code_hash) VALUES($1,$2,$3)`, i.Application, i.Subject, hash(normalized)); e != nil {
			return nil, e
		}
		out[n] = c
	}
	return out, nil
}
