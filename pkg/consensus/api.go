package consensus

import (
	"errors"
)

var (
	ErrInvalidHash      = errors.New("consensus: invalid hash (all-zero)")
	ErrInvalidSubmitter = errors.New("consensus: invalid submitter (empty)")
	ErrLabelTooLong     = errors.New("consensus: label exceeds maximum length")
	ErrRateLimited      = errors.New("consensus: rate limit exceeded (pending queue full)")
	ErrEngineStopped    = errors.New("consensus: engine stopped")
)

const (
	DefaultMaxLabelLen    = 256
	DefaultMaxTotalPending = 100000
	DefaultMaxPendingPerSubmitter = 5000
)

type APILimits struct {
	MaxLabelLen              int
	MaxTotalPending          int
	MaxPendingPerSubmitter   int
}

func DefaultAPILimits() APILimits {
	return APILimits{
		MaxLabelLen:             DefaultMaxLabelLen,
		MaxTotalPending:         DefaultMaxTotalPending,
		MaxPendingPerSubmitter:  DefaultMaxPendingPerSubmitter,
	}
}

func (e *Engine) SetAPILimits(cfg APILimits) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apiLimits = cfg
}

func (e *Engine) apiLimitsLocked() APILimits {
	if e.apiLimits.MaxLabelLen == 0 {
		return DefaultAPILimits()
	}
	return e.apiLimits
}

func validateEntry(hash [32]byte, submitter []byte, label string, cfg APILimits) error {
	if isZeroHash(hash) {
		return ErrInvalidHash
	}
	if len(submitter) == 0 {
		return ErrInvalidSubmitter
	}
	if len(label) > cfg.MaxLabelLen {
		return ErrLabelTooLong
	}
	return nil
}

func isZeroHash(h [32]byte) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

func (e *Engine) countPendingBySubmitter(submitter []byte) int {
	n := 0
	for _, entry := range e.pending {
		if string(entry.Submitter) == string(submitter) {
			n++
		}
	}
	return n
}
