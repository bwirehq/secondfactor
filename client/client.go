// Package client is the backend-only Go HTTP client for SecondFactor.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	sf "github.com/bwirehq/secondfactor"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	BaseURL, Audience, Application, KeyID string
	PrivateKey                            ed25519.PrivateKey
	HTTP                                  *http.Client
}
type Client struct{ config Config }

func New(c Config) (*Client, error) {
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Host == "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) || len(c.PrivateKey) != 64 || c.Application == "" || c.Audience == "" || c.KeyID == "" {
		return nil, sf.ErrInvalidInput
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	copyClient := *c.HTTP
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.HTTP = &copyClient
	c.PrivateKey = append(ed25519.PrivateKey(nil), c.PrivateKey...)
	return &Client{c}, nil
}
func (c *Client) Do(ctx context.Context, i sf.Identity, method, path string, body any, idempotency string, out any) error {
	if !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#%") {
		return sf.ErrInvalidInput
	}
	var raw []byte
	var e error
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	nonce := make([]byte, 24)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	now := time.Now().Unix()
	a, e := sf.SignAssertion(c.config.PrivateKey, c.config.KeyID, sf.AssertionClaims{IdempotencyHash: sf.BodyHash([]byte(idempotency)), Version: 1, Issuer: c.config.Application, Audience: c.config.Audience, Subject: i.Subject, Session: i.Session, Source: i.Source, IssuedAt: now, ExpiresAt: now + 60, ID: base64.RawURLEncoding.EncodeToString(nonce), Method: method, Path: path, BodyHash: sf.BodyHash(raw)})
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.config.BaseURL, "/")+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+a)
	req.Header.Set("Content-Type", "application/json")
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	res, e := c.config.HTTP.Do(req)
	if e != nil {
		return sf.ErrUnavailable
	}
	defer res.Body.Close()
	data, e := io.ReadAll(io.LimitReader(res.Body, 1048577))
	if e != nil || len(data) > 1048576 {
		return sf.ErrUnavailable
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var envelope struct {
			Error sf.Error `json:"error"`
		}
		if json.Unmarshal(data, &envelope) != nil || envelope.Error.Code == "" {
			return sf.ErrUnavailable
		}
		return &envelope.Error
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return sf.ErrUnavailable
	}
	return nil
}
func (c *Client) BeginEnrollment(ctx context.Context, in sf.Mutation) (sf.Enrollment, error) {
	var v sf.Enrollment
	e := c.Do(ctx, in.Identity, "POST", "/v1/enrollments", map[string]any{"account_name": in.AccountName, "proof": in.Proof}, in.IdempotencyKey, &v)
	return v, e
}
func (c *Client) ConfirmEnrollment(ctx context.Context, in sf.Mutation) (sf.Confirmation, error) {
	var v sf.Confirmation
	e := c.Do(ctx, in.Identity, "POST", "/v1/enrollments/confirm", map[string]any{"code": in.Code, "proof": in.Proof}, in.IdempotencyKey, &v)
	return v, e
}
func (c *Client) VerifyTOTP(ctx context.Context, in sf.Mutation) (sf.Verification, error) {
	var v sf.Verification
	e := c.Do(ctx, in.Identity, "POST", "/v1/verifications/totp", map[string]any{"code": in.Code}, "", &v)
	return v, e
}
func (c *Client) VerifyRecoveryCode(ctx context.Context, in sf.Mutation) (sf.Proof, error) {
	var v sf.Proof
	e := c.Do(ctx, in.Identity, "POST", "/v1/verifications/recovery-code", map[string]any{"code": in.Code}, "", &v)
	return v, e
}
func (c *Client) ValidateProof(ctx context.Context, i sf.Identity, proof string, purpose sf.ProofPurpose) error {
	return c.Do(ctx, i, "POST", "/v1/proofs/validate", map[string]any{"proof": proof, "purpose": purpose}, "", nil)
}
func (c *Client) Status(ctx context.Context, i sf.Identity) (sf.Status, error) {
	var v sf.Status
	e := c.Do(ctx, i, "GET", "/v1/factors/status", nil, "", &v)
	return v, e
}
func (c *Client) RegenerateRecoveryCodes(ctx context.Context, in sf.Mutation) ([]string, error) {
	var v struct {
		Codes []string `json:"recovery_codes"`
	}
	e := c.Do(ctx, in.Identity, "POST", "/v1/recovery-codes/regenerate", map[string]any{"proof": in.Proof}, in.IdempotencyKey, &v)
	return v.Codes, e
}
func (c *Client) ReplaceFactor(ctx context.Context, in sf.Mutation) (sf.Enrollment, error) {
	var v sf.Enrollment
	e := c.Do(ctx, in.Identity, "POST", "/v1/factors/replace", map[string]any{"account_name": in.AccountName, "proof": in.Proof}, in.IdempotencyKey, &v)
	return v, e
}
func (c *Client) RevokeFactor(ctx context.Context, in sf.Mutation) error {
	return c.Do(ctx, in.Identity, "DELETE", "/v1/factors", map[string]any{"proof": in.Proof}, in.IdempotencyKey, nil)
}
func (c *Client) RevokeSession(ctx context.Context, in sf.Mutation) error {
	return c.Do(ctx, in.Identity, "POST", "/v1/sessions/revoke", map[string]any{}, in.IdempotencyKey, nil)
}
func (c *Client) StartAssistedRecovery(ctx context.Context, in sf.Mutation) (sf.RecoveryJob, error) {
	var v sf.RecoveryJob
	e := c.Do(ctx, in.Identity, "POST", "/v1/assisted-recovery", map[string]any{"target": in.Target, "reason": in.Reason, "evidence": in.Evidence, "job_id": in.JobID}, in.IdempotencyKey, &v)
	return v, e
}
func (c *Client) ResumeAssistedRecovery(ctx context.Context, in sf.Mutation) (sf.RecoveryJob, error) {
	var v sf.RecoveryJob
	e := c.Do(ctx, in.Identity, "POST", "/v1/assisted-recovery/resume", map[string]any{"target": in.Target, "reason": in.Reason, "evidence": in.Evidence, "job_id": in.JobID}, "", &v)
	return v, e
}
func (c *Client) CompleteAssistedRecovery(ctx context.Context, in sf.Mutation) (sf.Proof, error) {
	var v sf.Proof
	e := c.Do(ctx, in.Identity, "POST", "/v1/assisted-recovery/complete", map[string]any{"job_id": in.JobID, "invitation": in.Invitation}, in.IdempotencyKey, &v)
	return v, e
}
func (c *Client) CancelAssistedRecovery(ctx context.Context, in sf.Mutation) error {
	return c.Do(ctx, in.Identity, "POST", "/v1/assisted-recovery/cancel", map[string]any{"target": in.Target, "reason": in.Reason, "evidence": in.Evidence, "job_id": in.JobID}, in.IdempotencyKey, nil)
}
func (c *Client) ClaimEvents(ctx context.Context, i sf.Identity) ([]sf.Event, error) {
	var v []sf.Event
	e := c.Do(ctx, i, "POST", "/v1/events/claim", map[string]any{}, "", &v)
	return v, e
}
func (c *Client) AckEvent(ctx context.Context, i sf.Identity, id, lease string) error {
	return c.Do(ctx, i, "POST", "/v1/events/ack", map[string]string{"event_id": id, "lease": lease}, "", nil)
}
