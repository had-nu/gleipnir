// Sliding window rate limiter per submitter.
package consensus

import (
	"sync"
	"time"
)

// SubmitterLimiter tracks pending entries per submitter with sliding window expiration.
type SubmitterLimiter struct {
	mu          sync.Mutex
	windows     map[string]*timeWindow
	maxPerWindow int
	windowDur    time.Duration
}

type timeWindow struct {
	mu      sync.Mutex
	entries []time.Time
}

func NewSubmitterLimiter(maxPerWindow int, windowDur time.Duration) *SubmitterLimiter {
	return &SubmitterLimiter{
		windows:      make(map[string]*timeWindow),
		maxPerWindow: maxPerWindow,
		windowDur:    windowDur,
	}
}

func (sl *SubmitterLimiter) Allow(submitter []byte) bool {
	key := string(submitter)
	sl.mu.Lock()
	w, ok := sl.windows[key]
	if !ok {
		w = &timeWindow{entries: make([]time.Time, 0, sl.maxPerWindow)}
		sl.windows[key] = w
	}
	sl.mu.Unlock()

	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-sl.windowDur)

	valid := w.entries[:0]
	for _, t := range w.entries {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	w.entries = valid

	if len(w.entries) >= sl.maxPerWindow {
		return false
	}

	w.entries = append(w.entries, now)
	return true
}

func (sl *SubmitterLimiter) Cleanup() {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-sl.windowDur * 2) // extra buffer

	for key, w := range sl.windows {
		w.mu.Lock()
		valid := w.entries[:0]
		for _, t := range w.entries {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		w.entries = valid
		if len(w.entries) == 0 {
			delete(sl.windows, key)
		}
		w.mu.Unlock()
	}
}