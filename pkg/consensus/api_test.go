//nolint:errcheck // test assertions
package consensus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/validation"
)

func chainEntry(hash [32]byte, submitter [16]byte, label string) chain.ProvenanceEntry {
	return chain.ProvenanceEntry{
		Hash:      hash,
		Submitter: submitter,
		Label:     label,
	}
}

func apiEngine() *Engine {
	var networkID [32]byte
	copy(networkID[:], []byte("api-test-network"))
	uid, _ := identity.NewUIDZero("api-test", networkID, true)
	node := Node{UID: *uid, Addr: "self"}
	eng := NewEngine(node, time.Hour)
	// Don't start the cycle loop - just test validation logic
	return eng
}

func TestSubmitValidation(t *testing.T) {
	eng := apiEngine()
	defer eng.Stop()
	ctx := context.Background()

	var submitter [16]byte
	copy(submitter[:], []byte("submitter"))

	// Zero hash rejected
	if _, err := eng.Submit(ctx, [32]byte{}, submitter, "label"); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("expected ErrInvalidHash, got %v", err)
	}

	// Empty submitter rejected
	if _, err := eng.Submit(ctx, [32]byte{1}, [16]byte{}, "label"); !errors.Is(err, ErrInvalidSubmitter) {
		t.Fatalf("expected ErrInvalidSubmitter, got %v", err)
	}

	// Oversized label rejected
	bigLabel := make([]byte, validation.DefaultAPILimits().MaxLabelLen+1)
	for i := range bigLabel {
		bigLabel[i] = 'a'
	}
	if _, err := eng.Submit(ctx, [32]byte{1}, submitter, string(bigLabel)); !errors.Is(err, ErrLabelTooLong) {
		t.Fatalf("expected ErrLabelTooLong, got %v", err)
	}

	// Valid submission accepted
	if _, err := eng.Submit(ctx, [32]byte{1}, submitter, "label"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnqueueValidation(t *testing.T) {
	eng := apiEngine()
	defer eng.Stop()

	var submitter [16]byte
	copy(submitter[:], []byte("s"))

	if err := eng.Enqueue(chainEntry([32]byte{}, submitter, "l")); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("expected ErrInvalidHash, got %v", err)
	}
	if err := eng.Enqueue(chainEntry([32]byte{5}, [16]byte{}, "l")); !errors.Is(err, ErrInvalidSubmitter) {
		t.Fatalf("expected ErrInvalidSubmitter, got %v", err)
	}
	if err := eng.Enqueue(chainEntry([32]byte{5}, submitter, "l")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRateLimitTotalPending(t *testing.T) {
	eng := apiEngine()
	defer eng.Stop()

	eng.SetAPILimits(APILimits{
		MaxLabelLen:             256,
		MaxTotalPending:         3,
		MaxPendingPerSubmitter:  100,
	})

	ctx := context.Background()
	// Fill up to the limit
	for i := 0; i < 3; i++ {
		h := [32]byte{byte(i + 1)}
		if _, err := eng.Submit(ctx, h, submitter, "l"); err != nil {
			t.Fatalf("submit %d failed: %v", i, err)
		}
	}
	// Next should be rate limited
	if _, err := eng.Submit(ctx, [32]byte{99}, submitter, "l"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

func TestRateLimitPerSubmitter(t *testing.T) {
	eng := apiEngine()
	defer eng.Stop()

	eng.SetAPILimits(APILimits{
		MaxLabelLen:             256,
		MaxTotalPending:         1000,
		MaxPendingPerSubmitter:  2,
	})

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		h := [32]byte{byte(i + 1)}
		if _, err := eng.Submit(ctx, h, submitter, "l"); err != nil {
			t.Fatalf("submit %d failed: %v", i, err)
		}
	}
	if _, err := eng.Submit(ctx, [32]byte{99}, submitter, "l"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	// Different submitter not affected by alice's cap
	var bob [16]byte
	copy(bob[:], []byte("bob"))
	if _, err := eng.Submit(ctx, [32]byte{98}, bob, "l"); err != nil {
		t.Fatalf("bob submit failed: %v", err)
	}
}

func TestSubmitAfterStop(t *testing.T) {
	eng := apiEngine()
	eng.Stop()
	ctx := context.Background()
	if _, err := eng.Submit(ctx, [32]byte{1}, submitter, "l"); err != ErrEngineStopped {
		t.Fatalf("expected ErrEngineStopped, got %v", err)
	}
}

func TestRunCyclePanicRecovery(t *testing.T) {
	eng := apiEngine()
	defer eng.Stop()

	// Inject a pending entry that will trigger a panic during SMT insert
	eng.Enqueue(chainEntry([32]byte{1}, submitter, "l"))
	eng.Enqueue(chainEntry([32]byte{2}, submitter, "l"))

	// Should not panic
	eng.RunCycle()
	eng.RunCycle()
}

var submitter [16]byte

func init() {
	copy(submitter[:], []byte("s"))
}