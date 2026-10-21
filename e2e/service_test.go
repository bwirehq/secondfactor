package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	sf "github.com/bwirehq/secondfactor"
	"github.com/bwirehq/secondfactor/client"
	"github.com/bwirehq/secondfactor/transport"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type host struct{}

func (host) VerifySession(ctx context.Context, i sf.Identity) (sf.Session, error) {
	return sf.Session{Subject: i.Subject, ID: i.Session, Active: true, AuthenticatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (host) AuthorizeRecovery(context.Context, sf.RecoveryRequest) (sf.RecoveryAuthorization, error) {
	return sf.RecoveryAuthorization{}, nil
}
func (host) RevokeSessions(context.Context, sf.RevocationRequest) (sf.Revocation, error) {
	return sf.Revocation{}, nil
}
func TestServiceAndSDKs(t *testing.T) {
	dsn := os.Getenv("SECONDFACTOR_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("SF_REQUIRE_DB") == "1" {
			t.Fatal("test database required")
		}
		t.Skip("isolated database not configured")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	schema := "sf_e2e_" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if e = sf.Migrate(ctx, p); e != nil {
		t.Fatal(e)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	s, e := sf.New(sf.Config{Pool: p, Applications: map[string]sf.Application{"test": {Issuer: "SecondFactor Test", Keys: map[string]ed25519.PublicKey{"test": private.Public().(ed25519.PublicKey)}}}, ActiveKeyID: "test", Keys: map[string][]byte{"test": bytes.Repeat([]byte{1}, 32)}, Sessions: host{}, Recovery: host{}, Revoker: host{}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RegisterApplications(ctx); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(&transport.Handler{Service: s, Audience: "secondfactor-test"})
	defer server.Close()
	c, e := client.New(client.Config{BaseURL: server.URL, Audience: "secondfactor-test", Application: "test", KeyID: "test", PrivateKey: private})
	if e != nil {
		t.Fatal(e)
	}
	i := sf.Identity{Application: "test", Subject: "owner", Session: "primary", Source: "test"}
	in := sf.Mutation{Identity: i, IdempotencyKey: "begin-enrollment-idem", AccountName: "owner@example.invalid"}
	setup, e := c.BeginEnrollment(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	in.IdempotencyKey = "confirm-enrollment-idem"
	in.AccountName = ""
	in.Code, _ = totp.GenerateCode(setup.Secret, time.Now())
	confirmed, e := c.ConfirmEnrollment(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.ValidateProof(ctx, i, confirmed.Verification.Access.Token, sf.AccessProof); e != nil {
		t.Fatal(e)
	}
	if _, e = c.ConfirmEnrollment(ctx, in); !errors.Is(e, sf.ErrSecretConsumed) {
		t.Fatal("retry", e)
	}
	if _, e = c.VerifyTOTP(ctx, in); !errors.Is(e, sf.ErrInvalidCode) {
		t.Fatal("confirmation code replay", e)
	}
	in.Code = ""
	in.Proof = confirmed.Verification.Sensitive.Token
	in.IdempotencyKey = "regenerate-codes-idem"
	if codes, e := c.RegenerateRecoveryCodes(ctx, in); e != nil || len(codes) != 10 {
		t.Fatal(e)
	}
	if c.ValidateProof(ctx, i, confirmed.Verification.Access.Token, sf.AccessProof) == nil {
		t.Fatal("revoked proof")
	}
	for _, path := range []string{"/v1/factors//status", "/v1/factors/%73tatus", "/v1/factors/status/", "/v1/factors/status?tenant=other"} {
		res, e := http.Get(server.URL + path)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("path normalization accepted %s: %d", path, res.StatusCode)
		}
	}
	if os.Getenv("SF_TEST_CLIENTS") == "1" {
		for _, v := range []struct {
			name, dir string
			args      []string
		}{{"typescript", "../sdk/typescript", []string{"node", "--test", "test/client.test.mjs"}}, {"rust", "../sdk/rust", []string{"cargo", "test", "--locked", "live_service"}}} {
			t.Run(v.name, func(t *testing.T) {
				cmd := exec.CommandContext(ctx, v.args[0], v.args[1:]...)
				cmd.Dir = v.dir
				cmd.Env = append(os.Environ(), "SF_TEST_URL="+server.URL)
				raw, e := cmd.CombinedOutput()
				if e != nil {
					t.Fatalf("SDK integration failed: %s", raw)
				}
			})
		}
	}
}
