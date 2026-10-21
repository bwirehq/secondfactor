package secondfactor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

type AssertionHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}
type AssertionClaims struct {
	IdempotencyHash string `json:"idh"`
	Version         int    `json:"ver"`
	Issuer          string `json:"iss"`
	Audience        string `json:"aud"`
	Subject         string `json:"sub"`
	Session         string `json:"sid"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
	ID              string `json:"jti"`
	Method          string `json:"htm"`
	Path            string `json:"htu"`
	BodyHash        string `json:"bsh"`
	Source          string `json:"src"`
}

func BodyHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func SignAssertion(key ed25519.PrivateKey, kid string, claims AssertionClaims) (string, error) {
	if len(key) != ed25519.PrivateKeySize || !validID(kid) {
		return "", ErrInvalidInput
	}
	h, _ := json.Marshal(AssertionHeader{"EdDSA", "sf-assertion+jwt", kid})
	p, e := json.Marshal(claims)
	if e != nil {
		return "", e
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input))), nil
}

// StrictJSON rejects duplicate keys, unknown fields, trailing values and oversized inputs.
func StrictJSON(raw []byte, dest any) error {
	if len(raw) > 16384 {
		return ErrInvalidInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if e := uniqueJSON(d); e != nil {
		return ErrInvalidInput
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalidInput
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dest) != nil {
		return ErrInvalidInput
	}
	return nil
}
func uniqueJSON(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return ErrInvalidInput
			}
			seen[s] = true
			if e = uniqueJSON(d); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = uniqueJSON(d); e != nil {
				return e
			}
		}
	default:
		return ErrInvalidInput
	}
	_, e = d.Token()
	return e
}
func CanonicalRequest(r *http.Request) bool {
	p := r.URL.Path
	return strings.HasPrefix(p, "/v1/") && r.URL.RawPath == "" && r.URL.RawQuery == "" && !r.URL.ForceQuery && path.Clean(p) == p && !strings.HasSuffix(p, "/") && !strings.Contains(r.RequestURI, "%")
}
func (s *Service) AuthenticateRequest(ctx context.Context, r *http.Request, body []byte, audience string) (Identity, error) {
	var empty Identity
	if !CanonicalRequest(r) || len(body) > 16384 || len(r.Header.Values("Idempotency-Key")) > 1 || len(r.Header.Values("Authorization")) > 1 {
		return empty, ErrDenied
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) > 8192 {
		return empty, ErrDenied
	}
	parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
	if len(parts) != 3 {
		return empty, ErrDenied
	}
	decode := base64.RawURLEncoding.DecodeString
	hr, e := decode(parts[0])
	if e != nil {
		return empty, ErrDenied
	}
	var h AssertionHeader
	if StrictJSON(hr, &h) != nil || h.Algorithm != "EdDSA" || h.Type != "sf-assertion+jwt" || !validID(h.KeyID) {
		return empty, ErrDenied
	}
	pr, e := decode(parts[1])
	if e != nil {
		return empty, ErrDenied
	}
	var c AssertionClaims
	if StrictJSON(pr, &c) != nil {
		return empty, ErrDenied
	}
	a, ok := s.apps[c.Issuer]
	if !ok {
		return empty, ErrDenied
	}
	// Privileged event delivery requires a separate application worker credential.
	// A user-context signing key can never claim tenant-wide recovery invitations.
	keys := a.Keys
	if r.URL.Path == "/v1/events/claim" || r.URL.Path == "/v1/events/ack" {
		keys = a.EventKeys
	}
	key := keys[h.KeyID]
	sig, e := decode(parts[2])
	if e != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return empty, ErrDenied
	}
	now := time.Now().Unix()
	if c.IdempotencyHash != BodyHash([]byte(r.Header.Get("Idempotency-Key"))) || c.Version != 1 || c.Audience != audience || audience == "" || c.IssuedAt > now+5 || c.IssuedAt < now-65 || c.ExpiresAt <= now-5 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 60 || !validID(c.ID) || c.Method != r.Method || c.Path != r.URL.Path || subtle.ConstantTimeCompare([]byte(c.BodyHash), []byte(BodyHash(body))) != 1 || !validText(c.Subject) || !validText(c.Session) || !validText(c.Source) {
		return empty, ErrDenied
	}
	tag, e := s.pool.Exec(ctx, `INSERT INTO secondfactor_assertion_replays(app_id,jti,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, c.Issuer, c.ID, time.Unix(c.ExpiresAt+5, 0))
	if e != nil {
		return empty, ErrUnavailable
	}
	if tag.RowsAffected() != 1 {
		return empty, ErrDenied
	}
	return Identity{c.Issuer, c.Subject, c.Session, c.Source}, nil
}
func (s *Service) Ready(ctx context.Context) error { return s.pool.Ping(ctx) }
