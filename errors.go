package secondfactor

import (
	"errors"
	"fmt"
	"time"
)

type Error struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

func (e *Error) Error() string        { return e.Code + ": " + e.Message }
func (e *Error) Is(target error) bool { var t *Error; return errors.As(target, &t) && e.Code == t.Code }

var (
	ErrInvalidInput    = &Error{Code: "invalid_input", Message: "Invalid input."}
	ErrInvalidCode     = &Error{Code: "invalid_code", Message: "Invalid, expired, or already used code."}
	ErrDenied          = &Error{Code: "denied", Message: "Authorization required."}
	ErrUnavailable     = &Error{Code: "unavailable", Message: "Security verification unavailable."}
	ErrConflict        = &Error{Code: "conflict", Message: "Security state changed; restart the operation."}
	ErrRecoveryPending = &Error{Code: "recovery_pending", Message: "Recovery must complete before this operation."}
	ErrSecretConsumed  = &Error{Code: "idempotent_secret_consumed", Message: "Operation completed; its one-time secret cannot be returned again."}
)

func limited(d time.Duration) error {
	return &Error{Code: "rate_limited", Message: "Too many attempts.", RetryAfter: max(1, int(d.Seconds()))}
}
func invalid(field string) error {
	return &Error{Code: "invalid_input", Message: fmt.Sprintf("Invalid %s.", field)}
}
