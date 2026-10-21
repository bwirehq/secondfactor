// This example's primary sessions are in memory and are NOT production authentication.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	sf "github.com/bwirehq/secondfactor"
	"github.com/bwirehq/secondfactor/client"
	"github.com/bwirehq/secondfactor/integration"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type record struct {
	Session sf.Session
	Proofs  sf.Verification
}
type host struct {
	mu         sync.Mutex
	sessions   map[string]record
	generation int64
	jobs       map[string]int64
	attempts   map[string]int
}

func (h *host) VerifySession(ctx context.Context, i sf.Identity) (sf.Session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[i.Session].Session, nil
}
func (h *host) AuthorizeRecovery(context.Context, sf.RecoveryRequest) (sf.RecoveryAuthorization, error) {
	return sf.RecoveryAuthorization{Allowed: false}, nil
}
func (h *host) RevokeSessions(ctx context.Context, r sf.RevocationRequest) (sf.Revocation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if gen, ok := h.jobs[r.JobID]; ok {
		return sf.Revocation{Confirmed: true, Generation: gen}, nil
	}
	h.generation++
	for id, v := range h.sessions {
		if v.Session.Subject == r.Subject {
			delete(h.sessions, id)
		}
	}
	h.jobs[r.JobID] = h.generation
	return sf.Revocation{Confirmed: true, Generation: h.generation}, nil
}
func readKey(path string) []byte {
	raw, e := os.ReadFile(path)
	if e != nil {
		log.Fatal("key unavailable")
	}
	b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if e != nil || len(b) != 32 {
		log.Fatal("invalid key")
	}
	return b
}
func main() {
	base := flag.String("service", "https://localhost:8443", "SecondFactor URL")
	cert := flag.String("cert", "secrets/dev.crt", "development certificate")
	key := flag.String("tls-key", "secrets/dev.key", "development TLS key")
	seedFile := flag.String("seed", "secrets/application.seed", "application signing seed")
	servicePub := flag.String("service-public", "secrets/service.seed.pub", "service callback public key")
	passwordFile := flag.String("password-file", "secrets/demo-password", "mock login password")
	origin := flag.String("origin", "https://localhost:9443", "browser origin")
	flag.Parse()
	password, e := os.ReadFile(*passwordFile)
	if e != nil {
		log.Fatal("demo password file required")
	}
	expected := sha256.Sum256([]byte(strings.TrimSpace(string(password))))
	ca, e := os.ReadFile(*cert)
	if e != nil {
		log.Fatal("CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		log.Fatal("invalid CA")
	}
	c, e := client.New(client.Config{BaseURL: *base, Audience: "secondfactor-local", Application: "demo", KeyID: "app1", PrivateKey: ed25519.NewKeyFromSeed(readKey(*seedFile)), HTTP: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}})
	if e != nil {
		log.Fatal("client configuration invalid")
	}
	h := &host{sessions: map[string]record{}, jobs: map[string]int64{}, attempts: map[string]int{}}
	mux := http.NewServeMux()
	mux.Handle("POST /callback", &integration.CallbackHandler{Application: "demo", ServiceKeys: map[string]ed25519.PublicKey{"service1": readKey(*servicePub)}, KeyID: "app1", PrivateKey: ed25519.NewKeyFromSeed(readKey(*seedFile)), Sessions: h, Recovery: h, Revoker: h})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" && (r.Header.Get("Origin") != *origin || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")) {
			http.Error(w, "origin or content type denied", 403)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		sourceHash := sha256.Sum256([]byte(ip))
		source := fmt.Sprintf("%x", sourceHash[:])
		var body struct {
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if r.Method != "GET" {
			raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
			if e != nil || sf.StrictJSON(raw, &body) != nil {
				http.Error(w, "invalid body", 400)
				return
			}
		}
		if r.Method == "POST" && r.URL.Path == "/login" {
			h.mu.Lock()
			bucket := fmt.Sprintf("%s:%d", source, time.Now().Unix()/600)
			h.attempts[bucket]++
			tries := h.attempts[bucket]
			for k := range h.attempts {
				if !strings.HasSuffix(k, fmt.Sprintf(":%d", time.Now().Unix()/600)) {
					delete(h.attempts, k)
				}
			}
			h.mu.Unlock()
			if tries > 5 {
				http.Error(w, "rate limited", 429)
				return
			}
			got := sha256.Sum256([]byte(body.Password))
			if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
				http.Error(w, "invalid login", 401)
				return
			}
			b := make([]byte, 32)
			if _, e = rand.Read(b); e != nil {
				http.Error(w, "unavailable", 503)
				return
			}
			id := base64.RawURLEncoding.EncodeToString(b)
			h.mu.Lock()
			h.sessions[id] = record{Session: sf.Session{Subject: "demo-user", ID: id, Active: true, AuthenticatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Generation: h.generation}}
			h.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "__Host-secondfactor_demo", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 3600})
			_ = json.NewEncoder(w).Encode(map[string]bool{"primary_authenticated": true})
			return
		}
		cookie, e := r.Cookie("__Host-secondfactor_demo")
		if e != nil {
			http.Error(w, "primary login required", 401)
			return
		}
		h.mu.Lock()
		rec, ok := h.sessions[cookie.Value]
		h.mu.Unlock()
		if !ok || !rec.Session.ExpiresAt.After(time.Now()) {
			http.Error(w, "primary login required", 401)
			return
		}
		identity := sf.Identity{Application: "demo", Subject: rec.Session.Subject, Session: rec.Session.ID, Source: source}
		b := make([]byte, 24)
		if _, e = rand.Read(b); e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		in := sf.Mutation{Identity: identity, IdempotencyKey: base64.RawURLEncoding.EncodeToString(b), Code: body.Code, Proof: rec.Proofs.Sensitive.Token, AccountName: "demo-user@example.invalid"}
		var out any
		var proofs *sf.Verification
		switch r.Method + " " + r.URL.Path {
		case "POST /mfa/enroll":
			out, e = c.BeginEnrollment(r.Context(), in)
		case "POST /mfa/confirm":
			var v sf.Confirmation
			v, e = c.ConfirmEnrollment(r.Context(), in)
			out = map[string]any{"recovery_codes": v.RecoveryCodes}
			proofs = &v.Verification
		case "POST /mfa/verify":
			var v sf.Verification
			v, e = c.VerifyTOTP(r.Context(), in)
			out = map[string]bool{"verified": e == nil}
			proofs = &v
		case "POST /mfa/regenerate":
			var codes []string
			codes, e = c.RegenerateRecoveryCodes(r.Context(), in)
			out = map[string]any{"recovery_codes": codes}
		case "GET /mfa/status":
			out, e = c.Status(r.Context(), identity)
		case "GET /protected":
			e = c.ValidateProof(r.Context(), identity, rec.Proofs.Access.Token, sf.AccessProof)
			out = map[string]string{"message": "Primary session and MFA proof verified."}
		case "POST /logout":
			e = c.RevokeSession(r.Context(), in)
			if e == nil {
				h.mu.Lock()
				delete(h.sessions, cookie.Value)
				h.mu.Unlock()
				http.SetCookie(w, &http.Cookie{Name: "__Host-secondfactor_demo", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
			}
			out = map[string]bool{"signed_out": e == nil}
		default:
			http.NotFound(w, r)
			return
		}
		if e != nil {
			http.Error(w, "operation denied or unavailable", 403)
			return
		}
		if proofs != nil {
			h.mu.Lock()
			rec.Proofs = *proofs
			h.sessions[cookie.Value] = rec
			h.mu.Unlock()
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	server := &http.Server{Addr: ":9443", Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 30 * time.Second}
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}
