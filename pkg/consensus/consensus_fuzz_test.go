package consensus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func TestFuzzEnqueueEdgeCases(t *testing.T) {
	uid, err := identity.NewUIDZero("fuzz-enqueue", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "fuzz-enqueue"}, time.Hour)
	defer eng.Stop()

	// Invalid entries are rejected; only valid ones are queued.
	invalid := []chain.ProvenanceEntry{
		{Hash: [32]byte{}, Submitter: [16]byte{}, Label: ""},
		{Hash: [32]byte{}, Submitter: [16]byte{}, Label: string(make([]byte, 1<<16))},
	}
	for _, e := range invalid {
		if err := eng.Enqueue(e); err == nil {
			t.Fatalf("expected validation error for %+v", e)
		}
	}

	valid := []chain.ProvenanceEntry{
		{Hash: [32]byte{255}, Submitter: [16]byte{}, Label: "normal"},
		{Hash: [32]byte{1, 2, 3}, Submitter: [16]byte{}, Label: "big-submitter"},
	}
	for _, e := range valid {
		var submitter [16]byte
		copy(submitter[:], []byte("ok"))
		e.Submitter = submitter
		if err := eng.Enqueue(e); err != nil {
			t.Fatalf("valid entry rejected: %v", err)
		}
	}

	// Run cycle — should not panic
	eng.RunCycle()
	t.Log("Enqueue edge cases handled without panic")
}

// Test that malformed submissions don't crash the engine
func TestMalformedSubmissions(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("malformed-test-network"))
	uid, err := identity.NewUIDZero("malformed-test", networkID, true)
	if err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(Node{UID: *uid, Addr: "malformed-test"}, time.Hour)
	defer eng.Stop()

	ctx := context.Background()

	// Zero hash should be rejected
	zeroHash := [32]byte{}
	var submitter [16]byte
	copy(submitter[:], uid.RootID[:])
	_, err = eng.Submit(ctx, zeroHash, submitter, "zero-hash")
	if !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("expected ErrInvalidHash, got %v", err)
	}

	// Empty submitter should be rejected
	nonZeroHash := [32]byte{}
	nonZeroHash[0] = 1
	_, err = eng.Submit(ctx, nonZeroHash, [16]byte{}, "empty-submitter")
	if !errors.Is(err, ErrInvalidSubmitter) {
		t.Fatalf("expected ErrInvalidSubmitter, got %v", err)
	}

	// Oversized label should be rejected
	bigLabel := string(make([]byte, 1000))
	_, err = eng.Submit(ctx, nonZeroHash, uid.RootID, bigLabel)
	if !errors.Is(err, ErrLabelTooLong) {
		t.Fatalf("expected ErrLabelTooLong, got %v", err)
	}

	// Valid submission should work
	validHash := [32]byte{255}
	ticket, err := eng.Submit(ctx, validHash, uid.RootID, "valid")
	if err != nil {
		t.Fatalf("valid submission should not error: %v", err)
	}
	if ticket == nil || ticket.Status != "pending" {
		t.Fatalf("unexpected ticket: %+v", ticket)
	}

	// After all malformed submissions, running a cycle should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RunCycle panicked after malformed submissions: %v", r)
		}
	}()
	eng.RunCycle()

	t.Log("All malformed submissions handled without panic or state corruption")
}