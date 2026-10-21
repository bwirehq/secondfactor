// Package transport provides SecondFactor's backend-only JSON HTTP API.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	sf "github.com/bwirehq/secondfactor"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"
)

type Handler struct {
	Service  *sf.Service
	Audience string
}
type input struct {
	Code        string          `json:"code,omitempty"`
	Proof       string          `json:"proof,omitempty"`
	AccountName string          `json:"account_name,omitempty"`
	Target      string          `json:"target,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	Evidence    string          `json:"evidence,omitempty"`
	JobID       string          `json:"job_id,omitempty"`
	Invitation  string          `json:"invitation,omitempty"`
	Purpose     sf.ProofPurpose `json:"purpose,omitempty"`
	EventID     string          `json:"event_id,omitempty"`
	Lease       string          `json:"lease,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if !sf.CanonicalRequest(r) {
		writeError(w, sf.ErrDenied)
		return
	}
	if r.Header.Get("Origin") != "" {
		writeError(w, sf.ErrDenied)
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if e != nil {
		writeError(w, sf.ErrInvalidInput)
		return
	}
	i, e := h.Service.AuthenticateRequest(ctx, r, body, h.Audience)
	if e != nil {
		writeError(w, e)
		return
	}
	var v input
	if len(body) > 0 {
		mt, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || mt != "application/json" || sf.StrictJSON(body, &v) != nil {
			writeError(w, sf.ErrInvalidInput)
			return
		}
	}
	allowed := map[string]map[string]bool{
		"POST /v1/enrollments":                 {"account_name": true, "proof": true},
		"POST /v1/enrollments/confirm":         {"code": true, "proof": true},
		"POST /v1/verifications/totp":          {"code": true},
		"POST /v1/verifications/sensitive":     {"code": true},
		"POST /v1/verifications/recovery-code": {"code": true},
		"POST /v1/proofs/validate":             {"proof": true, "purpose": true},
		"GET /v1/factors/status":               {},
		"POST /v1/recovery-codes/regenerate":   {"proof": true},
		"POST /v1/factors/replace":             {"account_name": true, "proof": true},
		"DELETE /v1/factors":                   {"proof": true},
		"POST /v1/sessions/revoke":             {},
		"POST /v1/assisted-recovery":           {"target": true, "reason": true, "evidence": true, "job_id": true},
		"POST /v1/assisted-recovery/resume":    {"target": true, "reason": true, "evidence": true, "job_id": true},
		"POST /v1/assisted-recovery/cancel":    {"target": true, "reason": true, "evidence": true, "job_id": true},
		"POST /v1/assisted-recovery/complete":  {"job_id": true, "invitation": true},
		"POST /v1/events/claim":                {},
		"POST /v1/events/ack":                  {"event_id": true, "lease": true},
		"GET /v1/health/ready":                 {},
	}
	if len(body) > 0 {
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil {
			writeError(w, sf.ErrInvalidInput)
			return
		}
		for key := range fields {
			if !allowed[r.Method+" "+r.URL.Path][key] {
				writeError(w, sf.ErrInvalidInput)
				return
			}
		}
	}
	in := sf.Mutation{Identity: i, IdempotencyKey: r.Header.Get("Idempotency-Key"), Code: v.Code, Proof: v.Proof, AccountName: v.AccountName, Target: v.Target, Reason: v.Reason, Evidence: v.Evidence, JobID: v.JobID, Invitation: v.Invitation}
	var result any = map[string]bool{"ok": true}
	switch r.Method + " " + r.URL.Path {
	case "POST /v1/enrollments":
		result, e = h.Service.BeginEnrollment(ctx, in)
	case "POST /v1/enrollments/confirm":
		result, e = h.Service.ConfirmEnrollment(ctx, in)
	case "POST /v1/verifications/totp", "POST /v1/verifications/sensitive":
		result, e = h.Service.VerifyTOTP(ctx, in)
	case "POST /v1/verifications/recovery-code":
		result, e = h.Service.VerifyRecoveryCode(ctx, in)
	case "POST /v1/proofs/validate":
		e = h.Service.ValidateProof(ctx, i, v.Proof, v.Purpose)
	case "GET /v1/factors/status":
		result, e = h.Service.Status(ctx, i)
	case "POST /v1/recovery-codes/regenerate":
		var codes []string
		codes, e = h.Service.RegenerateRecoveryCodes(ctx, in)
		result = map[string]any{"recovery_codes": codes}
	case "POST /v1/factors/replace":
		result, e = h.Service.ReplaceFactor(ctx, in)
	case "DELETE /v1/factors":
		e = h.Service.RevokeFactor(ctx, in)
	case "POST /v1/sessions/revoke":
		e = h.Service.RevokeSession(ctx, in)
	case "POST /v1/assisted-recovery":
		result, e = h.Service.StartAssistedRecovery(ctx, in)
	case "POST /v1/assisted-recovery/resume":
		result, e = h.Service.ResumeAssistedRecovery(ctx, in)
	case "POST /v1/assisted-recovery/complete":
		result, e = h.Service.CompleteAssistedRecovery(ctx, in)
	case "POST /v1/assisted-recovery/cancel":
		e = h.Service.CancelAssistedRecovery(ctx, in)
	case "POST /v1/events/claim":
		result, e = h.Service.ClaimEvents(ctx, i.Application, 20)
	case "POST /v1/events/ack":
		e = h.Service.AckEvent(ctx, i.Application, v.EventID, v.Lease)
	case "GET /v1/health/ready":
		e = h.Service.Ready(ctx)
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": &sf.Error{Code: "not_found", Message: "Unknown endpoint."}})
		return
	}
	if e != nil {
		writeError(w, e)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}
func writeError(w http.ResponseWriter, e error) {
	var v *sf.Error
	if !errors.As(e, &v) {
		v = sf.ErrUnavailable
	}
	status := http.StatusForbidden
	switch v.Code {
	case "invalid_input":
		status = 400
	case "invalid_code":
		status = 401
	case "conflict", "idempotent_secret_consumed", "recovery_pending":
		status = 409
	case "rate_limited":
		status = 429
	case "unavailable":
		status = 503
	}
	if v.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(v.RetryAfter))
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": v})
}
