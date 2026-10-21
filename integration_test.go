package secondfactor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testHost struct {
	mu                            sync.Mutex
	sessions                      map[string]Session
	generations                   map[string]int64
	jobs                          map[string]int64
	deny, failRevoke, failSession bool
	authorizations                int
}

func (h *testHost) login(subject, id string) Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := Session{Subject: subject, ID: id, Active: true, AuthenticatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Generation: h.generations[subject]}
	h.sessions[id] = v
	return v
}
func (h *testHost) VerifySession(ctx context.Context, i Identity) (Session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failSession {
		return Session{}, ErrUnavailable
	}
	return h.sessions[i.Session], nil
}
func (h *testHost) AuthorizeRecovery(ctx context.Context, r RecoveryRequest) (RecoveryAuthorization, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authorizations++
	return RecoveryAuthorization{!h.deny && r.Actor.Subject == "operator" && r.Actor.Subject != r.Target && r.Action != "", "policy-verified", h.generations[r.Target]}, nil
}
func (h *testHost) RevokeSessions(ctx context.Context, r RevocationRequest) (Revocation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failRevoke {
		return Revocation{}, ErrUnavailable
	}
	if gen, ok := h.jobs[r.JobID]; ok {
		return Revocation{true, gen}, nil
	}
	h.generations[r.Subject]++
	gen := h.generations[r.Subject]
	for id, v := range h.sessions {
		if v.Subject == r.Subject {
			v.Active = false
			h.sessions[id] = v
		}
	}
	h.jobs[r.JobID] = gen
	return Revocation{true, gen}, nil
}

type fixture struct {
	s   *Service
	p   *pgxpool.Pool
	h   *testHost
	i   Identity
	ctx context.Context
}

func database(t *testing.T, maxConns int32) *fixture {
	t.Helper()
	dsn := os.Getenv("SECONDFACTOR_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("SF_REQUIRE_DB") == "1" {
			t.Fatal("SECONDFACTOR_TEST_DATABASE_URL is required")
		}
		t.Skip("isolated PostgreSQL not configured")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := token()
	schema := "sf_" + strings.ToLower(strings.ReplaceAll(id[:12], "-", "x"))
	schema = strings.ReplaceAll(schema, "_", "x")
	if _, e = admin.Exec(ctx, `CREATE SCHEMA `+schema); e != nil {
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.MaxConns = maxConns
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { p.Close(); _, _ = admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`); admin.Close() })
	if e = Migrate(ctx, p); e != nil {
		t.Fatal(e)
	}
	h := &testHost{sessions: map[string]Session{}, generations: map[string]int64{}, jobs: map[string]int64{}}
	h.login("owner", "owner-session")
	h.login("operator", "operator-session")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
	eventKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
	s, e := New(Config{Pool: p, Applications: map[string]Application{"test": {Issuer: "Example", Keys: map[string]ed25519.PublicKey{"test": key}, EventKeys: map[string]ed25519.PublicKey{"worker": eventKey}}, "other": {Issuer: "Other", Keys: map[string]ed25519.PublicKey{"test": key}}}, ActiveKeyID: "one", Keys: map[string][]byte{"one": bytes.Repeat([]byte{1}, 32)}, Sessions: h, Recovery: h, Revoker: h})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RegisterApplications(ctx); e != nil {
		t.Fatal(e)
	}
	return &fixture{s, p, h, Identity{"test", "owner", "owner-session", "test-source"}, ctx}
}
func (f *fixture) in() Mutation {
	key, _ := token()
	return Mutation{Identity: f.i, IdempotencyKey: key}
}
func (f *fixture) enroll(t *testing.T) (Enrollment, Confirmation) {
	t.Helper()
	in := f.in()
	in.AccountName = "owner@example.invalid"
	setup, e := f.s.BeginEnrollment(f.ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	in = f.in()
	in.Code, _ = totp.GenerateCode(setup.Secret, time.Now())
	c, e := f.s.ConfirmEnrollment(f.ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	return setup, c
}
func TestDatabaseLifecycle(t *testing.T) {
	f := database(t, 4)
	_, c := f.enroll(t)
	if len(c.RecoveryCodes) != 10 {
		t.Fatal("missing codes")
	}
	if e := f.s.ValidateProof(f.ctx, f.i, c.Verification.Access.Token, AccessProof); e != nil {
		t.Fatal(e)
	}
	if e := f.s.ValidateProof(f.ctx, f.i, c.Verification.Access.Token, SensitiveProof); !errors.Is(e, ErrDenied) {
		t.Fatal("cross-purpose")
	}
	other := f.i
	other.Application = "other"
	if f.s.ValidateProof(f.ctx, other, c.Verification.Access.Token, AccessProof) == nil {
		t.Fatal("cross tenant")
	}
	other = f.i
	other.Session = "another"
	f.h.login("owner", other.Session)
	if f.s.ValidateProof(f.ctx, other, c.Verification.Access.Token, AccessProof) == nil {
		t.Fatal("cross session")
	}
	status, e := f.s.Status(f.ctx, f.i)
	if e != nil || !status.Enrolled || status.RemainingRecoveryCodes != 10 {
		t.Fatal(status, e)
	}
	in := f.in()
	in.Proof = c.Verification.Sensitive.Token
	codes, e := f.s.RegenerateRecoveryCodes(f.ctx, in)
	if e != nil || len(codes) != 10 {
		t.Fatal(e)
	}
	if f.s.ValidateProof(f.ctx, f.i, c.Verification.Access.Token, AccessProof) == nil {
		t.Fatal("version proof survived")
	}
	if _, e = f.s.RegenerateRecoveryCodes(f.ctx, in); !errors.Is(e, ErrSecretConsumed) {
		t.Fatal("idempotent secret repeated", e)
	}
	in = f.in()
	in.Code = c.RecoveryCodes[0]
	if _, e = f.s.VerifyRecoveryCode(f.ctx, in); !errors.Is(e, ErrInvalidCode) {
		t.Fatal("old codes survived")
	}
	in.Code = codes[0]
	grant, e := f.s.VerifyRecoveryCode(f.ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	if f.s.ValidateProof(f.ctx, f.i, grant.Token, AccessProof) == nil {
		t.Fatal("recovery grants access")
	}
	in = f.in()
	in.Proof = grant.Token
	in.AccountName = "owner@example.invalid"
	setup, e := f.s.ReplaceFactor(f.ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	in = f.in()
	in.Proof = grant.Token
	in.Code, _ = totp.GenerateCode(setup.Secret, time.Now())
	next, e := f.s.ConfirmEnrollment(f.ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	in = f.in()
	in.Proof = next.Verification.Sensitive.Token
	if e = f.s.RevokeFactor(f.ctx, in); e != nil {
		t.Fatal(e)
	}
	status, e = f.s.Status(f.ctx, f.i)
	if e != nil || status.Enrolled {
		t.Fatal("factor not revoked")
	}
}
func TestDatabaseReplayConcurrency(t *testing.T) {
	for _, kind := range []string{"totp", "recovery"} {
		t.Run(kind, func(t *testing.T) {
			f := database(t, 8)
			setup, c := f.enroll(t)
			_, _ = f.p.Exec(f.ctx, `UPDATE secondfactor_factors SET last_verified_time_step=-1`)
			var success atomic.Int32
			var wg sync.WaitGroup
			for n := 0; n < 8; n++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					in := f.in()
					var e error
					if kind == "totp" {
						in.Code, _ = totp.GenerateCode(setup.Secret, time.Now())
						_, e = f.s.VerifyTOTP(f.ctx, in)
					} else {
						in.Code = c.RecoveryCodes[0]
						_, e = f.s.VerifyRecoveryCode(f.ctx, in)
					}
					if e == nil {
						success.Add(1)
					}
				}()
			}
			wg.Wait()
			if success.Load() != 1 {
				t.Fatalf("success count %d", success.Load())
			}
		})
	}
}
func TestDatabaseFailureCommitSingleConnection(t *testing.T) {
	f := database(t, 1)
	f.enroll(t)
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	for n := 0; n < 5; n++ {
		in := f.in()
		in.Code = "invalid"
		if _, e := f.s.VerifyTOTP(ctx, in); !errors.Is(e, ErrInvalidCode) {
			t.Fatal(e)
		}
	}
	var failures int
	if e := f.p.QueryRow(ctx, `SELECT failures FROM secondfactor_factors WHERE app_id='test' AND subject='owner'`).Scan(&failures); e != nil || failures != 5 {
		t.Fatal("failures did not commit", failures, e)
	}
	in := f.in()
	in.Code = "000000"
	_, e := f.s.VerifyTOTP(ctx, in)
	var typed *Error
	if !errors.As(e, &typed) || typed.Code != "rate_limited" {
		t.Fatal(e)
	}
}
func TestDatabaseRollbackAndExpiry(t *testing.T) {
	f := database(t, 4)
	in := f.in()
	in.AccountName = "owner@example.invalid"
	setup, e := f.s.BeginEnrollment(f.ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.BeginEnrollment(f.ctx, f.in()); !errors.Is(e, ErrInvalidInput) {
		t.Fatal(e)
	}
	in = f.in()
	in.AccountName = "owner@example.invalid"
	if _, e = f.s.BeginEnrollment(f.ctx, in); !errors.Is(e, ErrConflict) {
		t.Fatal("duplicate", e)
	}
	_, _ = f.p.Exec(f.ctx, `UPDATE secondfactor_enrollments SET expires_at=clock_timestamp()-interval '1 second'`)
	in = f.in()
	in.Code, _ = totp.GenerateCode(setup.Secret, time.Now())
	if _, e = f.s.ConfirmEnrollment(f.ctx, in); !errors.Is(e, ErrConflict) {
		t.Fatal("expired enrollment", e)
	}
	status, _ := f.s.Status(f.ctx, f.i)
	if status.Enrolled {
		t.Fatal("expired transition persisted")
	}
	_, _ = f.p.Exec(f.ctx, `DELETE FROM secondfactor_enrollments`)
	_, c := f.enroll(t)
	_, _ = f.p.Exec(f.ctx, `UPDATE secondfactor_proofs SET expires_at=clock_timestamp()-interval '1 second'`)
	if f.s.ValidateProof(f.ctx, f.i, c.Verification.Access.Token, AccessProof) == nil {
		t.Fatal("expired proof")
	}
	f.h.mu.Lock()
	f.h.failSession = true
	f.h.mu.Unlock()
	if f.s.ValidateProof(f.ctx, f.i, c.Verification.Access.Token, AccessProof) == nil {
		t.Fatal("callback failure bypass")
	}
}
func TestDatabaseAssistedRecovery(t *testing.T) {
	f := database(t, 4)
	_, c := f.enroll(t)
	admin := Identity{"test", "operator", "operator-session", "admin-source"}
	in := f.in()
	in.Identity = admin
	in.Target = "owner"
	in.Reason = "Identity independently verified"
	in.Evidence = "policy-ticket-1"
	in.JobID = "job1"
	f.h.deny = true
	if _, e := f.s.StartAssistedRecovery(f.ctx, in); !errors.Is(e, ErrDenied) {
		t.Fatal("unauthorized", e)
	}
	f.h.deny = false
	f.h.failRevoke = true
	if _, e := f.s.StartAssistedRecovery(f.ctx, in); !errors.Is(e, ErrUnavailable) {
		t.Fatal("revocation failure", e)
	}
	if f.s.ValidateProof(f.ctx, f.i, c.Verification.Access.Token, AccessProof) == nil {
		t.Fatal("pending recovery granted access")
	}
	var count int
	_ = f.p.QueryRow(f.ctx, `SELECT count(*) FROM secondfactor_events WHERE kind='session_revocation_required'`).Scan(&count)
	if count != 1 {
		t.Fatal("missing transactional event")
	}
	f.h.failRevoke = false
	job, e := f.s.ResumeAssistedRecovery(f.ctx, in)
	if e != nil || job.State != "invited" {
		t.Fatal(job, e)
	}
	events, e := f.s.ClaimEvents(f.ctx, "test", 100)
	if e != nil {
		t.Fatal(e)
	}
	invitation := ""
	for _, v := range events {
		if v.Kind == "recovery_invitation" {
			invitation = stringField(v.Delivery, "invitation")
		}
	}
	if invitation == "" {
		t.Fatal("invitation missing")
	}
	f.h.login("owner", "owner-new-session")
	f.i.Session = "owner-new-session"
	complete := f.in()
	complete.JobID = "job1"
	complete.Invitation = invitation
	grant, e := f.s.CompleteAssistedRecovery(f.ctx, complete)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.CompleteAssistedRecovery(f.ctx, complete); !errors.Is(e, ErrSecretConsumed) {
		t.Fatal("invitation repeated", e)
	}
	if f.s.ValidateProof(f.ctx, f.i, grant.Token, AccessProof) == nil {
		t.Fatal("invitation grants access")
	}
	begin := f.in()
	begin.Proof = grant.Token
	begin.AccountName = "owner@example.invalid"
	setup, e := f.s.ReplaceFactor(f.ctx, begin)
	if e != nil {
		t.Fatal(e)
	}
	confirm := f.in()
	confirm.Proof = grant.Token
	confirm.Code, _ = totp.GenerateCode(setup.Secret, time.Now())
	if _, e = f.s.ConfirmEnrollment(f.ctx, confirm); e != nil {
		t.Fatal(e)
	}
}
func TestDatabaseCancelNeverDisables(t *testing.T) {
	f := database(t, 4)
	f.enroll(t)
	in := f.in()
	in.Identity = Identity{"test", "operator", "operator-session", "admin"}
	in.Target = "owner"
	in.Reason = "Independent verification completed"
	in.Evidence = "policy"
	in.JobID = "cancel-job"
	if _, e := f.s.StartAssistedRecovery(f.ctx, in); e != nil {
		t.Fatal(e)
	}
	in.IdempotencyKey, _ = token()
	if e := f.s.CancelAssistedRecovery(f.ctx, in); e != nil {
		t.Fatal(e)
	}
	f.h.login("owner", "new-session")
	f.i.Session = "new-session"
	status, e := f.s.Status(f.ctx, f.i)
	if e != nil || !status.Enrolled || !status.RecoveryPending {
		t.Fatal("cancel bypass", status, e)
	}
}
func TestDatabaseKeyRotation(t *testing.T) {
	f := database(t, 4)
	_, c := f.enroll(t)
	f.s.keys["two"] = bytes.Repeat([]byte{2}, 32)
	f.s.active = "two"
	if n, e := f.s.ReencryptBatch(f.ctx, 10); e != nil || n < 1 {
		t.Fatal(n, e)
	}
	usage, e := f.s.KeyUsage(f.ctx)
	if e != nil || usage["one"] != 0 {
		t.Fatal(usage, e)
	}
	delete(f.s.keys, "one")
	if e = f.s.CheckKeyCoverage(f.ctx); e != nil {
		t.Fatal(e)
	}
	if e = f.s.ValidateProof(f.ctx, f.i, c.Verification.Access.Token, AccessProof); e != nil {
		t.Fatal("rotation changed proof", e)
	}
}
func TestDatabaseAssertionAuthentication(t *testing.T) {
	f := database(t, 4)
	seed := bytes.Repeat([]byte{7}, 32)
	now := time.Now().Unix()
	claims := AssertionClaims{IdempotencyHash: BodyHash(nil), Version: 1, Issuer: "test", Audience: "audience", Subject: "owner", Session: "owner-session", Source: "source", IssuedAt: now, ExpiresAt: now + 60, ID: "assertion1", Method: "GET", Path: "/v1/factors/status", BodyHash: BodyHash(nil)}
	assertion, _ := SignAssertion(ed25519.NewKeyFromSeed(seed), "test", claims)
	req := httptest.NewRequest("GET", claims.Path, nil)
	req.Header.Set("Authorization", "Bearer "+assertion)
	if _, e := f.s.AuthenticateRequest(f.ctx, req, nil, "audience"); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.AuthenticateRequest(f.ctx, req, nil, "audience"); !errors.Is(e, ErrDenied) {
		t.Fatal("replay", e)
	}
	for n, change := range []func(*AssertionClaims){func(c *AssertionClaims) { c.Audience = "wrong" }, func(c *AssertionClaims) { c.BodyHash = BodyHash([]byte("tamper")) }, func(c *AssertionClaims) { c.Method = "POST" }, func(c *AssertionClaims) { c.ExpiresAt = now - 60 }, func(c *AssertionClaims) { c.IdempotencyHash = BodyHash([]byte("different")) }} {
		c := claims
		c.ID = fmt.Sprintf("bad%d", n)
		change(&c)
		a, _ := SignAssertion(ed25519.NewKeyFromSeed(seed), "test", c)
		req.Header.Set("Authorization", "Bearer "+a)
		if _, e := f.s.AuthenticateRequest(f.ctx, req, nil, "audience"); e == nil {
			t.Fatal("tampered accepted")
		}
	}
}
func TestDatabaseConfigValidation(t *testing.T) {
	f := database(t, 4)
	for _, change := range []func(*Config){func(c *Config) { c.Pool = nil }, func(c *Config) { c.ActiveKeyID = "missing" }, func(c *Config) { c.Keys = map[string][]byte{"one": {1}} }, func(c *Config) { c.Sessions = nil }, func(c *Config) { c.Recovery = nil }, func(c *Config) { c.Revoker = nil }, func(c *Config) { c.Limits = Limits{Account: -1} }, func(c *Config) { c.Applications = map[string]Application{"test": {}} }} {
		c := Config{Pool: f.p, ActiveKeyID: "one", Keys: f.s.keys, Applications: f.s.apps, Sessions: f.h, Recovery: f.h, Revoker: f.h}
		change(&c)
		if _, e := New(c); e == nil {
			t.Fatal("bad config accepted")
		}
	}
}

func TestDatabaseSharedLimitsAndMissingSource(t *testing.T) {
	f := database(t, 4)
	f.enroll(t)
	f.s.limits.Account = 3
	replica := *f.s
	for n := 0; n < 3; n++ {
		in := f.in()
		in.Code = "invalid"
		_, e := replica.VerifyTOTP(f.ctx, in)
		if n < 1 && e != nil && !errors.Is(e, ErrInvalidCode) {
			t.Fatal(e)
		}
	}
	in := f.in()
	in.Code = "invalid"
	_, e := f.s.VerifyTOTP(f.ctx, in)
	var typed *Error
	if !errors.As(e, &typed) || typed.Code != "rate_limited" {
		t.Fatal("replica bypass", e)
	}
	in.Identity.Source = ""
	if _, e = f.s.VerifyTOTP(f.ctx, in); !errors.Is(e, ErrDenied) {
		t.Fatal("missing source bypass", e)
	}
}
func TestDatabaseTransactionRollback(t *testing.T) {
	f := database(t, 4)
	in := f.in()
	in.AccountName = "owner@example.invalid"
	setup, e := f.s.BeginEnrollment(f.ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.p.Exec(f.ctx, `CREATE FUNCTION reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test rollback'; END $$; CREATE TRIGGER reject_event BEFORE INSERT ON secondfactor_events FOR EACH ROW EXECUTE FUNCTION reject_event()`)
	if e != nil {
		t.Fatal(e)
	}
	in = f.in()
	in.Code, _ = totp.GenerateCode(setup.Secret, time.Now())
	if _, e = f.s.ConfirmEnrollment(f.ctx, in); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	status, e := f.s.Status(f.ctx, f.i)
	if e != nil || status.Enrolled || status.RemainingRecoveryCodes != 0 {
		t.Fatal("partial transition persisted", status, e)
	}
	_, _ = f.p.Exec(f.ctx, `DROP TRIGGER reject_event ON secondfactor_events`)
	if _, e = f.s.ConfirmEnrollment(f.ctx, in); e != nil {
		t.Fatal("rollback consumed code/idempotency", e)
	}
}
func TestDatabaseExpiryAfterLockWait(t *testing.T) {
	f := database(t, 4)
	_, c := f.enroll(t)
	_, e := f.p.Exec(f.ctx, `UPDATE secondfactor_proofs SET expires_at=clock_timestamp()+interval '100 milliseconds'`)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := f.p.Begin(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer rollback(tx)
	if _, e = tx.Exec(f.ctx, `SELECT 1 FROM secondfactor_factors WHERE app_id='test' AND subject='owner' FOR UPDATE`); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- f.s.ValidateProof(f.ctx, f.i, c.Verification.Access.Token, AccessProof) }()
	time.Sleep(250 * time.Millisecond)
	if e = tx.Commit(f.ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, ErrDenied) {
		t.Fatal("expired while locked proof accepted", e)
	}
}
func TestDatabaseRecoveryRejectsOldSessionGeneration(t *testing.T) {
	f := database(t, 4)
	f.enroll(t)
	in := f.in()
	in.Identity = Identity{"test", "operator", "operator-session", "admin-source"}
	in.Target = "owner"
	in.Reason = "Independent identity verification"
	in.Evidence = "ticket"
	in.JobID = "generation-job"
	if _, e := f.s.StartAssistedRecovery(f.ctx, in); e != nil {
		t.Fatal(e)
	}
	events, e := f.s.ClaimEvents(f.ctx, "test", 100)
	if e != nil {
		t.Fatal(e)
	}
	var invitation string
	for _, event := range events {
		if event.Kind == "recovery_invitation" {
			invitation = stringField(event.Delivery, "invitation")
		}
	}
	if invitation == "" {
		t.Fatal("missing invitation")
	}
	f.h.login("owner", "new")
	f.h.mu.Lock()
	v := f.h.sessions["new"]
	v.Generation = 0
	v.AuthenticatedAt = time.Now().Add(2 * time.Second)
	f.h.sessions["new"] = v
	f.h.mu.Unlock()
	f.i.Session = "new"
	complete := f.in()
	complete.JobID = "generation-job"
	complete.Invitation = invitation
	if _, e = f.s.CompleteAssistedRecovery(f.ctx, complete); !errors.Is(e, ErrDenied) {
		t.Fatal("old generation allowed", e)
	}
	f.h.mu.Lock()
	v.Generation = 1
	v.AuthenticatedAt = time.Now().Add(-time.Minute)
	f.h.sessions["new"] = v
	f.h.mu.Unlock()
	if _, e = f.s.CompleteAssistedRecovery(f.ctx, complete); !errors.Is(e, ErrDenied) {
		t.Fatal("old authentication allowed", e)
	}
	f.h.login("owner", "fresh")
	complete.Identity.Session = "fresh"
	if _, e = f.s.CompleteAssistedRecovery(f.ctx, complete); e != nil {
		t.Fatal("valid invitation lost by rejected attempts", e)
	}
}
func TestDatabaseEventLeases(t *testing.T) {
	f := database(t, 4)
	f.enroll(t)
	events, e := f.s.ClaimEvents(f.ctx, "test", 100)
	if e != nil || len(events) == 0 {
		t.Fatal(e)
	}
	other, e := f.s.ClaimEvents(f.ctx, "test", 100)
	if e != nil || len(other) != 0 {
		t.Fatal("double lease", e)
	}
	event := events[0]
	if f.s.AckEvent(f.ctx, "other", event.ID, event.Lease) == nil {
		t.Fatal("cross tenant acknowledgment")
	}
	if e = f.s.AckEvent(f.ctx, "test", event.ID, event.Lease); e != nil {
		t.Fatal(e)
	}
	if f.s.AckEvent(f.ctx, "test", event.ID, event.Lease) == nil {
		t.Fatal("replayed lease")
	}
}

func TestDatabaseDeniedRecoveryAuthorizationIsLimited(t *testing.T) {
	f := database(t, 4)
	f.h.deny = true
	f.s.limits.Sensitive = 2
	in := f.in()
	in.Identity = Identity{"test", "operator", "operator-session", "admin-source"}
	in.Target = "owner"
	in.JobID = "denied-job"
	in.Reason = "Independent identity verification"
	in.Evidence = "ticket"
	for n := 0; n < 2; n++ {
		if _, e := f.s.StartAssistedRecovery(f.ctx, in); !errors.Is(e, ErrDenied) {
			t.Fatal(e)
		}
	}
	if _, e := f.s.StartAssistedRecovery(f.ctx, in); e == nil || e.(*Error).Code != "rate_limited" {
		t.Fatal("denied recovery not limited", e)
	}
	if f.h.authorizations != 2 {
		t.Fatal("excess policy callbacks", f.h.authorizations)
	}
}

// TestDatabaseEventSigningKeyIsolation prevents hijacking privileged outbox delivery
// through an ordinary authenticated application's end-user signing credentials.
func TestDatabaseEventSigningKeyIsolation(t *testing.T) {
	f := database(t, 4)
	now := time.Now().Unix()
	claims := AssertionClaims{IdempotencyHash: BodyHash(nil), Version: 1, Issuer: "test",
		Audience: "audience", Subject: "owner", Session: "owner-session", Source: "worker",
		IssuedAt: now, ExpiresAt: now + 60, Method: "POST",
		Path: "/v1/events/claim", BodyHash: BodyHash([]byte("{}"))}
	for _, tc := range []struct {
		name       string
		seed       byte
		path       string
		authorized bool
	}{
		{"user-key-to-events", 7, "/v1/events/claim", false},
		{"worker-key-to-events", 8, "/v1/events/claim", true},
		{"worker-key-to-user-endpoint", 8, "/v1/factors/status", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := claims
			c.Path = tc.path
			c.ID = tc.name
			a, e := SignAssertion(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{tc.seed}, 32)), map[byte]string{7: "test", 8: "worker"}[tc.seed], c)
			if e != nil {
				t.Fatal(e)
			}
			req := httptest.NewRequest("POST", c.Path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+a)
			_, e = f.s.AuthenticateRequest(f.ctx, req, []byte("{}"), "audience")
			if (e == nil) != tc.authorized {
				t.Fatalf("authorized=%v error=%v", tc.authorized, e)
			}
		})
	}
}

func TestDatabaseRejectsSharedEventSigningKey(t *testing.T) {
	f := database(t, 4)
	regular := f.s.apps["test"].Keys["test"]
	_, err := New(Config{
		Pool: f.p,
		Applications: map[string]Application{
			"test": {
				Issuer: "Example",
				Keys: map[string]ed25519.PublicKey{"normal": regular},
				EventKeys: map[string]ed25519.PublicKey{"events": regular},
			},
		},
		ActiveKeyID: "one",
		Keys: map[string][]byte{"one": bytes.Repeat([]byte{1}, 32)},
		Sessions: f.h,
		Recovery: f.h,
		Revoker: f.h,
	})
	if err == nil {
		t.Fatal("shared ordinary and event signing material accepted")
	}
}
