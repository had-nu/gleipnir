// Package validation provides client-side submission validation.
// Use this before submitting to avoid round-trips for invalid entries.
package validation

import (
	"errors"
	"fmt"
)

// ErrInvalidHash is returned when the hash is all zeros.
var ErrInvalidHash = errors.New("invalid hash: all-zero hash not allowed")

// ErrInvalidSubmitter is returned when the submitter is empty.
var ErrInvalidSubmitter = errors.New("invalid submitter: empty submitter not allowed")

// ErrLabelTooLong is returned when the label exceeds the maximum length.
var ErrLabelTooLong = errors.New("label too long: max 256 bytes")

// ErrRateLimited is returned when rate limits are exceeded.
var ErrRateLimited = errors.New("rate limit exceeded")

// ErrEngineStopped is returned when the engine has been stopped.
var ErrEngineStopped = errors.New("engine stopped: no longer accepting submissions")

// DefaultAPILimits returns the default validation limits.
func DefaultAPILimits() APILimits {
	return APILimits{
		MaxLabelLen:        256,
		MaxTotalPending:    100000,
		MaxPendingPerSubmitter: 5000,
	}
}

// APILimits defines validation limits.
type APILimits struct {
	MaxLabelLen             int
	MaxTotalPending         int
	MaxPendingPerSubmitter int
}

// ValidateEntry validates a submission entry against the given limits.
func ValidateEntry(hash [32]byte, submitter []byte, label string, limits APILimits) error {
	if IsZeroHash(hash) {
		return WrapValidationError(ErrCodeInvalidHash, "invalid hash", ErrInvalidHash)
	}
	if len(submitter) == 0 {
		return WrapValidationError(ErrCodeInvalidSubmitter, "invalid submitter", ErrInvalidSubmitter)
	}
	if len(label) > limits.MaxLabelLen {
		return WrapValidationError(ErrCodeLabelTooLong, "label too long", ErrLabelTooLong)
	}
	return nil
}

// IsZeroHash checks if a hash is all zeros (exported for external use).
func IsZeroHash(hash [32]byte) bool {
	for _, b := range hash {
		if b != 0 {
			return false
		}
	}
	return true
}

// Error code constants for programmatic error handling.
const (
	ErrCodeInvalidHash       = "INVALID_HASH"
	ErrCodeInvalidSubmitter  = "INVALID_SUBMITTER"
	ErrCodeLabelTooLong      = "LABEL_TOO_LONG"
	ErrCodeRateLimited       = "RATE_LIMITED"
	ErrCodeEngineStopped     = "ENGINE_STOPPED"
)

// ValidationError wraps validation errors with a machine-readable code.
type ValidationError struct {
	Code    string
	Message string
	Err     error
}

func (e *ValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// WrapValidationError wraps an error with a validation error code.
func WrapValidationError(code, msg string, err error) *ValidationError {
	return &ValidationError{
		Code:    code,
		Message: msg,
		Err:     err,
	}
}

// FromError extracts validation error code from an error chain.
func FromError(err error) (string, bool) {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve.Code, true
	}
	return "", false
}