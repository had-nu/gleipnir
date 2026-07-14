package consensus

import (
	"time"

	"github.com/had-nu/gleipnir/pkg/validation"
)

var (
	ErrInvalidHash      = validation.ErrInvalidHash
	ErrInvalidSubmitter = validation.ErrInvalidSubmitter
	ErrLabelTooLong     = validation.ErrLabelTooLong
	ErrRateLimited      = validation.ErrRateLimited
	ErrEngineStopped    = validation.ErrEngineStopped
)

type APILimits = validation.APILimits

func DefaultAPILimits() APILimits {
	return validation.DefaultAPILimits()
}

func (e *Engine) SetAPILimits(cfg APILimits) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apiLimits = cfg
	// Update rate limiter if present
	if e.rateLimiter != nil {
		// Create new rate limiter with updated limits
		e.rateLimiter = NewSubmitterLimiter(cfg.MaxPendingPerSubmitter, time.Minute)
	}
}

func (e *Engine) apiLimitsLocked() APILimits {
	if e.apiLimits.MaxLabelLen == 0 {
		return DefaultAPILimits()
	}
	return e.apiLimits
}

func validateEntry(hash [32]byte, submitter []byte, label string, cfg APILimits) error {
	if validation.IsZeroHash(hash) {
		return validation.WrapValidationError(validation.ErrCodeInvalidHash, "invalid hash", ErrInvalidHash)
	}
	if len(submitter) == 0 {
		return validation.WrapValidationError(validation.ErrCodeInvalidSubmitter, "invalid submitter", ErrInvalidSubmitter)
	}
	if len(label) > cfg.MaxLabelLen {
		return validation.WrapValidationError(validation.ErrCodeLabelTooLong, "label too long", ErrLabelTooLong)
	}
	return nil
}