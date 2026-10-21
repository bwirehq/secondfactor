package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	sf "github.com/bwirehq/secondfactor"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestDestinationPolicy(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "169.254.169.254", "10.1.2.3", "172.16.0.1", "192.168.1.1", "::ffff:127.0.0.1", "100.100.100.200", "fe80::1", "0.0.0.0"} {
		if AllowedIP(netip.MustParseAddr(s), nil) {
			t.Fatal("unsafe", s)
		}
	}
	if !AllowedIP(netip.MustParseAddr("127.0.0.1"), []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}) {
		t.Fatal("explicit allowlist")
	}
	if _, e := SecureHTTP(Destination{URL: "http://example.invalid/callback"}); e == nil {
		t.Fatal("insecure callback")
	}
}

type host struct{}

func (host) VerifySession(ctx context.Context, i sf.Identity) (sf.Session, error) {
	return sf.Session{Subject: i.Subject, ID: i.Session, Active: true, AuthenticatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (host) AuthorizeRecovery(context.Context, sf.RecoveryRequest) (sf.RecoveryAuthorization, error) {
	return sf.RecoveryAuthorization{}, nil
}
func (host) RevokeSessions(context.Context, sf.RevocationRequest) (sf.Revocation, error) {
	return sf.Revocation{}, nil
}
func TestSignedCallbacks(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	apub, apriv, _ := ed25519.GenerateKey(rand.Reader)
	h := &CallbackHandler{Application: "test", ServiceKeys: map[string]ed25519.PublicKey{"service": pub}, PrivateKey: apriv, KeyID: "app", Sessions: host{}, Recovery: host{}, Revoker: host{}}
	p, _ := json.Marshal(sf.Identity{Application: "test", Subject: "u", Session: "s", Source: "test"})
	m := Message{1, "request1", "test", "session.verify", time.Now().Unix(), p}
	b, _ := json.Marshal(m)
	req := httptest.NewRequest("POST", "/callback", bytes.NewReader(b))
	req.Header.Set("X-SecondFactor-Key-ID", "service")
	req.Header.Set("X-SecondFactor-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, b)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(w.Header().Get("X-SecondFactor-Signature"))
	if !ed25519.Verify(apub, w.Body.Bytes(), sig) {
		t.Fatal("response not authenticated")
	}
}
