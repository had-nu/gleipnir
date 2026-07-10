package consensus

import (
	"context"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

// GLP-T-C04 — Malformed submission handling.
// Fuzz Submit() with various malformed inputs.
func FuzzSubmitMalformed(f *testing.F) {
	seeds := []struct {
		hash   []byte
		label  string
	}{
		{make([]byte, 0), ""},
		{make([]byte, 32), ""},
		{make([]byte, 32), "normal"},
		{make([]byte, 32), string(make([]byte, 1<<16))},
		{nil, ""},
		{nil, "nil-hash"},
	}
	for _, s := range seeds {
		f.Add(s.hash, s.label)
	}
	f.Fuzz(func(t *testing.T, hash []byte, label string) {
		uid := identity.NewUIDZero("fuzz-node", true)
		eng := NewEngine(Node{UID: *uid, Addr: "fuzz"}, time.Hour)
		defer eng.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		var h [32]byte
		if len(hash) >= 32 {
			copy(h[:], hash[:32])
		} else {
			copy(h[:], hash)
		}

		// Submit should never panic
		ticket, err := eng.Submit(ctx, h, uid.RootID, label)
		if err != nil {
			// Error is acceptable (e.g., context deadline), panic is not
			return
		}
		if ticket == nil {
			t.Fatal("Submit returned nil ticket without error")
		}
	})
}

// Explicit edge cases not covered by random fuzzing
func TestMalformedSubmissions(t *testing.T) {
	uid := identity.NewUIDZero("malformed-node", true)
	eng := NewEngine(Node{UID: *uid, Addr: "malformed"}, time.Hour)
	defer eng.Stop()
	ctx := context.Background()

	t.Run("nil submitter rejected", func(t *testing.T) {
		var h [32]byte
		h[0] = 1
		_, err := eng.Submit(ctx, h, nil, "nil-submitter")
		if err != ErrInvalidSubmitter {
			t.Fatalf("expected ErrInvalidSubmitter, got %v", err)
		}
	})

	t.Run("oversized label rejected", func(t *testing.T) {
		var h [32]byte
		h[0] = 2
		big := string(make([]byte, 1<<20)) // 1 MB label
		_, err := eng.Submit(ctx, h, uid.RootID, big)
		if err != ErrLabelTooLong {
			t.Fatalf("expected ErrLabelTooLong, got %v", err)
		}
	})

	t.Run("zero hash rejected", func(t *testing.T) {
		var zero [32]byte
		_, err := eng.Submit(ctx, zero, uid.RootID, "zero-hash")
		if err != ErrInvalidHash {
			t.Fatalf("expected ErrInvalidHash, got %v", err)
		}
	})

	t.Run("valid submission accepted", func(t *testing.T) {
		var h [32]byte
		h[0] = 3
		ticket, err := eng.Submit(ctx, h, uid.RootID, "valid")
		if err != nil {
			t.Fatalf("valid submission should not error: %v", err)
		}
		if ticket == nil || ticket.Status != "pending" {
			t.Fatalf("unexpected ticket: %+v", ticket)
		}
	})

	t.Run("colliding pending hash", func(t *testing.T) {
		var h [32]byte
		h[0] = 99
		for i := 0; i < 10; i++ {
			ticket, err := eng.Submit(ctx, h, uid.RootID, "collision")
			if err != nil {
				t.Fatalf("Submit should handle multiple submissions of same hash: %v", err)
			}
			if ticket == nil || ticket.Status != "pending" {
				t.Fatalf("unexpected ticket: %+v", ticket)
			}
		}
	})

	// After all malformed submissions, running a cycle should not panic
	t.Run("cycle after malformed input", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("RunCycle panicked after malformed submissions: %v", r)
			}
		}()
		eng.RunCycle()
	})

	t.Log("All malformed submissions handled without panic or state corruption")
}

// Fuzz the Enqueue path directly (lower-level than Submit)
func TestFuzzEnqueueEdgeCases(t *testing.T) {
	uid := identity.NewUIDZero("fuzz-enqueue", true)
	eng := NewEngine(Node{UID: *uid, Addr: "fuzz-enqueue"}, time.Hour)
	defer eng.Stop()

	// Invalid entries are rejected; only valid ones are queued.
	invalid := []chain.ProvenanceEntry{
		{Hash: [32]byte{}, Submitter: nil, Label: ""},
		{Hash: [32]byte{}, Submitter: []byte{}, Label: string(make([]byte, 1<<16))},
	}
	for _, e := range invalid {
		if err := eng.Enqueue(e); err == nil {
			t.Fatalf("expected validation error for %+v", e)
		}
	}

	valid := []chain.ProvenanceEntry{
		{Hash: [32]byte{255}, Submitter: []byte("ok"), Label: "normal"},
		{Hash: [32]byte{1, 2, 3}, Submitter: []byte("ok2"), Label: "big-submitter"},
	}
	for _, e := range valid {
		if err := eng.Enqueue(e); err != nil {
			t.Fatalf("valid entry rejected: %v", err)
		}
	}

	// Run cycle — should not panic
	eng.RunCycle()
	t.Log("Enqueue edge cases handled without panic")
}
