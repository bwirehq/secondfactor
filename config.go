// Package secondfactor implements application-independent, session-bound TOTP MFA.
// All Identity values must originate in trusted authenticated backend middleware.
package secondfactor

import (
	"context"
	"crypto/ed25519"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type Identity struct {
	Application string `json:"application"`
	Subject     string `json:"subject"`
	Session     string `json:"session"`
	Source      string `json:"source"`
}
type Session struct {
	Subject         string    `json:"subject"`
	ID              string    `json:"id"`
	Active          bool      `json:"active"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Generation      int64     `json:"generation"`
}

// SessionVerifier must query authoritative primary session state, not simply decode claims.
type SessionVerifier interface {
	VerifySession(context.Context, Identity) (Session, error)
}
type RecoveryAuthorization struct {
	Allowed          bool   `json:"allowed"`
	DecisionID       string `json:"decision_id"`
	TargetGeneration int64  `json:"target_generation"`
}
type RecoveryRequest struct {
	Action   string   `json:"action"`
	Actor    Identity `json:"actor"`
	Target   string   `json:"target"`
	Reason   string   `json:"reason"`
	Evidence string   `json:"evidence"`
	JobID    string   `json:"job_id"`
}
type RecoveryAuthorizer interface {
	AuthorizeRecovery(context.Context, RecoveryRequest) (RecoveryAuthorization, error)
}
type RevocationRequest struct {
	Application        string `json:"application"`
	Subject            string `json:"subject"`
	JobID              string `json:"job_id"`
	PreviousGeneration int64  `json:"previous_generation"`
}
type Revocation struct {
	Confirmed  bool  `json:"confirmed"`
	Generation int64 `json:"generation"`
}

// Revocation must be durable and idempotent by JobID. Confirmed means all older-generation sessions are unusable.
type SessionRevoker interface {
	RevokeSessions(context.Context, RevocationRequest) (Revocation, error)
}
type Application struct {
	Issuer string
	Keys   map[string]ed25519.PublicKey
}
type Limits struct {
	Account, Session, Source, Application, Sensitive, Failures int
	Window, Block                                              time.Duration
}

func DefaultLimits() Limits {
	return Limits{30, 30, 100, 10000, 10, 5, 10 * time.Minute, 10 * time.Minute}
}

type Config struct {
	Pool         *pgxpool.Pool
	Applications map[string]Application
	ActiveKeyID  string
	Keys         map[string][]byte
	Sessions     SessionVerifier
	Recovery     RecoveryAuthorizer
	Revoker      SessionRevoker
	Limits       Limits
}
type Service struct {
	pool     *pgxpool.Pool
	apps     map[string]Application
	active   string
	keys     map[string][]byte
	sessions SessionVerifier
	recovery RecoveryAuthorizer
	revoker  SessionRevoker
	limits   Limits
}

func New(c Config) (*Service, error) {
	if c.Pool == nil || c.Sessions == nil || c.Recovery == nil || c.Revoker == nil || len(c.Applications) == 0 || len(c.Keys) == 0 || !validID(c.ActiveKeyID) || len(c.Keys[c.ActiveKeyID]) != 32 {
		return nil, invalid("configuration")
	}
	if c.Limits == (Limits{}) {
		c.Limits = DefaultLimits()
	}
	l := c.Limits
	if l.Account < 1 || l.Session < 1 || l.Source < 1 || l.Application < 1 || l.Sensitive < 1 || l.Failures < 1 || l.Window < time.Second || l.Window > time.Hour || l.Block < time.Second || l.Block > time.Hour {
		return nil, invalid("limits")
	}
	s := &Service{pool: c.Pool, apps: map[string]Application{}, active: c.ActiveKeyID, keys: map[string][]byte{}, sessions: c.Sessions, recovery: c.Recovery, revoker: c.Revoker, limits: l}
	for id, k := range c.Keys {
		if !validID(id) || len(k) != 32 {
			return nil, invalid("key")
		}
		s.keys[id] = append([]byte(nil), k...)
	}
	for id, a := range c.Applications {
		if !validID(id) || len(a.Issuer) < 1 || len(a.Issuer) > 128 {
			return nil, invalid("application")
		}
		b := Application{Issuer: a.Issuer, Keys: map[string]ed25519.PublicKey{}}
		for kid, k := range a.Keys {
			if !validID(kid) || len(k) != 32 {
				return nil, invalid("signing key")
			}
			b.Keys[kid] = append(ed25519.PublicKey(nil), k...)
		}
		s.apps[id] = b
	}
	return s, nil
}
func validID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func validText(s string) bool {
	if len(s) < 1 || len(s) > 512 {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func (s *Service) session(ctx context.Context, i Identity) (Session, error) {
	if _, ok := s.apps[i.Application]; !ok || !validText(i.Subject) || !validText(i.Session) || !validText(i.Source) {
		return Session{}, ErrDenied
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	v, e := s.sessions.VerifySession(c, i)
	if e != nil {
		return Session{}, ErrUnavailable
	}
	n := time.Now()
	if !v.Active || v.Subject != i.Subject || v.ID != i.Session || !v.ExpiresAt.After(n) || v.AuthenticatedAt.IsZero() || v.AuthenticatedAt.After(n.Add(5*time.Second)) || v.Generation < 0 {
		return Session{}, ErrDenied
	}
	return v, nil
}
