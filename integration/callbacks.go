// Package integration implements the authenticated application callback protocol.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	sf "github.com/bwirehq/secondfactor"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

type Message struct {
	Version     int             `json:"version"`
	ID          string          `json:"id"`
	Application string          `json:"application"`
	Operation   string          `json:"operation"`
	IssuedAt    int64           `json:"issued_at"`
	Payload     json.RawMessage `json:"payload"`
}
type Response struct {
	ID          string          `json:"id"`
	Application string          `json:"application"`
	Operation   string          `json:"operation"`
	Payload     json.RawMessage `json:"payload"`
}
type Destination struct {
	URL          string
	Keys         map[string]ed25519.PublicKey
	AllowedCIDRs []netip.Prefix
	Roots        *x509.CertPool
}
type Callbacks struct {
	KeyID        string
	PrivateKey   ed25519.PrivateKey
	Applications map[string]Destination
}

func AllowedIP(ip netip.Addr, allow []netip.Prefix) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
func SecureHTTP(d Destination) (*http.Client, error) {
	u, e := url.Parse(d.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, sf.ErrInvalidInput
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.Roots}, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, DisableKeepAlives: true}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			if !AllowedIP(ip, d.AllowedCIDRs) {
				return nil, errors.New("callback destination prohibited")
			}
		}
		var last error
		for _, ip := range ips {
			conn, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		if last == nil {
			last = errors.New("callback resolution empty")
		}
		return nil, last
	}
	return &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func (c *Callbacks) call(ctx context.Context, app, operation string, payload any, out any) error {
	d, ok := c.Applications[app]
	if !ok || len(c.PrivateKey) != 64 {
		return sf.ErrUnavailable
	}
	h, e := SecureHTTP(d)
	if e != nil {
		return e
	}
	defer h.CloseIdleConnections()
	nonce := make([]byte, 24)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	p, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	m := Message{1, base64.RawURLEncoding.EncodeToString(nonce), app, operation, time.Now().Unix(), p}
	raw, e := json.Marshal(m)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SecondFactor-Key-ID", c.KeyID)
	req.Header.Set("X-SecondFactor-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.PrivateKey, raw)))
	res, e := h.Do(req)
	if e != nil {
		return sf.ErrUnavailable
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 16385))
	if e != nil || len(b) > 16384 || res.StatusCode != 200 {
		return sf.ErrUnavailable
	}
	key := d.Keys[res.Header.Get("X-SecondFactor-Key-ID")]
	sig, e := base64.RawURLEncoding.DecodeString(res.Header.Get("X-SecondFactor-Signature"))
	if e != nil || len(key) != 32 || !ed25519.Verify(key, b, sig) {
		return sf.ErrUnavailable
	}
	var reply Response
	if sf.StrictJSON(b, &reply) != nil || reply.ID != m.ID || reply.Application != app || reply.Operation != operation {
		return sf.ErrUnavailable
	}
	if sf.StrictJSON(reply.Payload, out) != nil {
		return sf.ErrUnavailable
	}
	return nil
}
func (c *Callbacks) VerifySession(ctx context.Context, i sf.Identity) (sf.Session, error) {
	var v sf.Session
	e := c.call(ctx, i.Application, "session.verify", i, &v)
	return v, e
}
func (c *Callbacks) AuthorizeRecovery(ctx context.Context, r sf.RecoveryRequest) (sf.RecoveryAuthorization, error) {
	var v sf.RecoveryAuthorization
	e := c.call(ctx, r.Actor.Application, "recovery.authorize", r, &v)
	return v, e
}
func (c *Callbacks) RevokeSessions(ctx context.Context, r sf.RevocationRequest) (sf.Revocation, error) {
	var v sf.Revocation
	e := c.call(ctx, r.Application, "sessions.revoke", r, &v)
	return v, e
}

// CallbackHandler authenticates the service and signs correlated responses. Business
// implementations must make revocation durable and idempotent using JobID.
// CallbackReplayGuard must atomically consume callback IDs across all application replicas.
// Use durable shared storage in production; duplicate IDs must return false.
type CallbackReplayGuard interface {
	Consume(context.Context, string, string, time.Time) (bool, error)
}

// MemoryReplayGuard is ONLY for local development and tests. It is not
// safe for distributed or restarting production applications.
type MemoryReplayGuard struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{used: make(map[string]time.Time)}
}

func (g *MemoryReplayGuard) Consume(_ context.Context, app, id string, expiry time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, until := range g.used {
		if !until.After(now) {
			delete(g.used, k)
		}
	}
	key := app + ":" + id
	if _, exists := g.used[key]; exists {
		return false, nil
	}
	g.used[key] = expiry
	return true, nil
}

type CallbackHandler struct {
	Replay      CallbackReplayGuard
	Application string
	ServiceKeys map[string]ed25519.PublicKey
	KeyID       string
	PrivateKey  ed25519.PrivateKey
	Sessions    sf.SessionVerifier
	Recovery    sf.RecoveryAuthorizer
	Revoker     sf.SessionRevoker
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "denied", 403)
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	key := h.ServiceKeys[r.Header.Get("X-SecondFactor-Key-ID")]
	sig, se := base64.RawURLEncoding.DecodeString(r.Header.Get("X-SecondFactor-Signature"))
	if e != nil || se != nil || len(key) != 32 || len(h.PrivateKey) != 64 || !ed25519.Verify(key, raw, sig) {
		http.Error(w, "denied", 403)
		return
	}
	var m Message
	now := time.Now().Unix()
	if sf.StrictJSON(raw, &m) != nil || m.Version != 1 || m.Application != h.Application || len(m.ID) < 16 || len(m.ID) > 128 || m.IssuedAt < now-5 || m.IssuedAt > now+5 {
		http.Error(w, "denied", 403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	// Never execute a signed administrative callback twice within its valid window.
	// Missing or unavailable replay storage must fail closed.
	if h.Replay == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	fresh, replayErr := h.Replay.Consume(ctx, m.Application, m.ID, time.Unix(m.IssuedAt+10, 0))
	if replayErr != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !fresh {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	var out any
	switch m.Operation {
	case "session.verify":
		var i sf.Identity
		if sf.StrictJSON(m.Payload, &i) != nil || i.Application != h.Application {
			e = sf.ErrDenied
		} else {
			out, e = h.Sessions.VerifySession(ctx, i)
		}
	case "recovery.authorize":
		var v sf.RecoveryRequest
		if sf.StrictJSON(m.Payload, &v) != nil || v.Actor.Application != h.Application {
			e = sf.ErrDenied
		} else {
			out, e = h.Recovery.AuthorizeRecovery(ctx, v)
		}
	case "sessions.revoke":
		var v sf.RevocationRequest
		if sf.StrictJSON(m.Payload, &v) != nil || v.Application != h.Application {
			e = sf.ErrDenied
		} else {
			out, e = h.Revoker.RevokeSessions(ctx, v)
		}
	default:
		e = sf.ErrDenied
	}
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	payload, _ := json.Marshal(out)
	b, e := json.Marshal(Response{m.ID, h.Application, m.Operation, payload})
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-SecondFactor-Key-ID", h.KeyID)
	w.Header().Set("X-SecondFactor-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(h.PrivateKey, b)))
	_, _ = w.Write(b)
}
