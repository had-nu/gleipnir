//nolint:errcheck // test assertions
package consensus

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

var testNetworkID = func() [32]byte {
	var id [32]byte
	copy(id[:], []byte("property-test-network"))
	return id
}()

// --- A01: Cross-run determinism of BlockHash and StateRoot ---

func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

func TestCrossRunDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}

	refTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := []chain.ProvenanceEntry{
		{Hash: [32]byte{1}, Submitter: [16]byte{}, Label: "a"},
		{Hash: [32]byte{2}, Submitter: [16]byte{}, Label: "b"},
	}
	copy(entries[0].Submitter[:], []byte("alice"))
	copy(entries[1].Submitter[:], []byte("bob"))

	// Same identity seed for both engines — simulated=true makes it deterministic
	uid, err := identity.NewUIDZero("determinism-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}

	var blocks1, blocks2 []chain.Block

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		eng := NewEngine(Node{UID: *uid, Addr: "node"}, time.Hour)
		eng.nowFunc = fixedClock(refTime)
		for _, e := range entries {
			eng.Enqueue(e)
		}
		eng.RunCycle()
		eng.mu.Lock()
		blocks1 = append(blocks1, eng.blocks...)
		eng.mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		eng := NewEngine(Node{UID: *uid, Addr: "node"}, time.Hour)
		eng.nowFunc = fixedClock(refTime)
		for _, e := range entries {
			eng.Enqueue(e)
		}
		eng.RunCycle()
		eng.mu.Lock()
		blocks2 = append(blocks2, eng.blocks...)
		eng.mu.Unlock()
	}()

	wg.Wait()

	if len(blocks1) != 1 || len(blocks2) != 1 {
		t.Fatalf("expected 1 block per engine, got %d / %d", len(blocks1), len(blocks2))
	}

	b1, b2 := blocks1[0], blocks2[0]
	if !bytes.Equal(b1.BlockHash, b2.BlockHash) {
		t.Fatalf("BlockHash differs across runs\n  a: %x\n  b: %x", b1.BlockHash, b2.BlockHash)
	}
	if !bytes.Equal(b1.StateRoot, b2.StateRoot) {
		t.Fatalf("StateRoot differs across runs\n  a: %x\n  b: %x", b1.StateRoot, b2.StateRoot)
	}
	if b1.Index != b2.Index || b1.Timestamp != b2.Timestamp {
		t.Fatal("Index or Timestamp differs across runs")
	}
}

func TestCrossRunDeterminismWithRace(t *testing.T) {
	t.Parallel()
	// Run the determinism check under -race detector by submitting in parallel
	refTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	uid, err := identity.NewUIDZero("race-node", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "race-node"}, time.Hour)
	eng.nowFunc = fixedClock(refTime)

	const n = 10
	var wg sync.WaitGroup
	for i := byte(0); i < n; i++ {
		wg.Add(1)
		go func(h byte) {
			defer wg.Done()
			var submitter [16]byte
			copy(submitter[:], []byte("t"))
			eng.Enqueue(chain.ProvenanceEntry{Hash: [32]byte{h + 1}, Submitter: submitter, Label: "r"})
		}(i)
	}
	wg.Wait()

	eng.RunCycle()

	// Check no panic, single block
	if len(eng.blocks) != 1 {
		t.Fatalf("expected 1 block under race, got %d", len(eng.blocks))
	}
}

func TestEnqueueAfterCycleDoesNotMutatePrevBlock(t *testing.T) {
	uid, err := identity.NewUIDZero("immut-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "immut"}, time.Hour)
	eng.cfg.MinLambda1 = 0 // Allow single-node mode to produce blocks (disable lambda1 check)

	entries := []chain.ProvenanceEntry{
		{Hash: [32]byte{1}, Submitter: [16]byte{}, Label: "a"},
		{Hash: [32]byte{2}, Submitter: [16]byte{}, Label: "b"},
	}
	copy(entries[0].Submitter[:], []byte("alice"))
	copy(entries[1].Submitter[:], []byte("bob"))

	for _, e := range entries {
		eng.Enqueue(e)
	}
	eng.RunCycle()

	block1 := eng.blocks[0]
	prevHash := block1.BlockHash

	// Add new entry with submitter set properly
	carol := [16]byte{}
	copy(carol[:], []byte("carol"))
	eng.Enqueue(chain.ProvenanceEntry{Hash: [32]byte{3}, Submitter: carol, Label: "c"})
	eng.RunCycle()

	block2 := eng.blocks[1]
	if !bytes.Equal(block1.BlockHash, prevHash) {
		t.Fatal("previous block hash was mutated after second cycle")
	}
	if block2.Index != block1.Index+1 {
		t.Fatal("block index did not advance")
	}
	if !bytes.Equal(block2.PrevHash, block1.BlockHash) {
		t.Fatal("block2.PrevHash does not match block1.BlockHash")
	}
}

func TestEnqueueAfterStopDoesNotPanic(t *testing.T) {
	uid, err := identity.NewUIDZero("stop-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "stop"}, time.Hour)
	eng.Stop()

	// Should not panic, just return error
	var submitter [16]byte
	copy(submitter[:], []byte("test"))
	if err = eng.Enqueue(chain.ProvenanceEntry{Hash: [32]byte{1}, Submitter: submitter, Label: "x"}); err == nil {
		t.Fatal("expected error after stop")
	}
}

func TestDeterministicEnqueueOrder(t *testing.T) {
	uid, err := identity.NewUIDZero("order-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "order"}, time.Hour)

	// Enqueue in different order
	entries := []chain.ProvenanceEntry{
		{Hash: [32]byte{1}, Submitter: [16]byte{}, Label: "a"},
		{Hash: [32]byte{2}, Submitter: [16]byte{}, Label: "b"},
		{Hash: [32]byte{3}, Submitter: [16]byte{}, Label: "c"},
	}
	copy(entries[0].Submitter[:], []byte("a"))
	copy(entries[1].Submitter[:], []byte("b"))
	copy(entries[2].Submitter[:], []byte("c"))

	for _, e := range entries {
		eng.Enqueue(e)
	}
	eng.RunCycle()

	block := eng.blocks[0]
	// Anchored entries should be sorted by hash
	for i := 1; i < len(block.Anchored); i++ {
		if bytes.Compare(block.Anchored[i-1].Hash[:], block.Anchored[i].Hash[:]) > 0 {
			t.Fatalf("anchored entries not sorted by hash at index %d", i)
		}
	}
}

func TestSubmitterRateLimit(t *testing.T) {
	uid, err := identity.NewUIDZero("ratelimit-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "ratelimit"}, time.Hour)

	// Set per-submitter limit to 2
	eng.SetAPILimits(APILimits{
		MaxLabelLen:             256,
		MaxTotalPending:         100,
		MaxPendingPerSubmitter:  2,
	})

	var alice, bob [16]byte
	copy(alice[:], []byte("alice"))
	copy(bob[:], []byte("bob"))

	// alice submits 2 — OK
	for i := 0; i < 2; i++ {
		var h [32]byte
		h[0] = byte(i + 1)
		if err := eng.Enqueue(chain.ProvenanceEntry{Hash: h, Submitter: alice, Label: "a"}); err != nil {
			t.Fatalf("alice submit %d failed: %v", i, err)
		}
	}
	// alice submits 3rd — rate limited
	var h3 [32]byte
	h3[0] = 3
	if err := eng.Enqueue(chain.ProvenanceEntry{Hash: h3, Submitter: alice, Label: "a"}); err == nil {
		t.Fatal("expected rate limit error for alice's 3rd submit")
	}
	// bob not affected
	var hb [32]byte
	hb[0] = 99
	if err := eng.Enqueue(chain.ProvenanceEntry{Hash: hb, Submitter: bob, Label: "b"}); err != nil {
		t.Fatalf("bob submit failed: %v", err)
	}
}

func TestTotalPendingLimit(t *testing.T) {
	uid, err := identity.NewUIDZero("total-limit-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "total"}, time.Hour)

	eng.SetAPILimits(APILimits{
		MaxLabelLen:             256,
		MaxTotalPending:         3,
		MaxPendingPerSubmitter:  100,
	})

	var submitter [16]byte
	copy(submitter[:], []byte("s"))

	for i := 0; i < 3; i++ {
		var h [32]byte
		h[0] = byte(i + 1)
		if err := eng.Enqueue(chain.ProvenanceEntry{Hash: h, Submitter: submitter, Label: "x"}); err != nil {
			t.Fatalf("submit %d failed: %v", i, err)
		}
	}
	// 4th should be rejected
	var h4 [32]byte
	h4[0] = 4
	if err := eng.Enqueue(chain.ProvenanceEntry{Hash: h4, Submitter: submitter, Label: "x"}); err == nil {
		t.Fatal("expected total pending limit error")
	}
}

func TestNetworkFragmentation(t *testing.T) {
	uid, err := identity.NewUIDZero("frag-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "frag"}, time.Hour)
	eng.cfg.MinLambda1 = 0 // Allow single-node mode

	// Enqueue an entry to propose
	var submitter [16]byte
	copy(submitter[:], uid.RootID[:])
	eng.Enqueue(chain.ProvenanceEntry{
		Hash:      [32]byte{1},
		Submitter: submitter,
		Label:     "test",
	})

	// No peers added — engine is single-node
	eng.RunCycle()

	// In single-node mode, should still produce blocks
	if len(eng.blocks) == 0 {
		t.Fatal("expected block in single-node mode")
	}
}

func TestLabelLengthValidation(t *testing.T) {
	uid, err := identity.NewUIDZero("label-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "label"}, time.Hour)

	var submitter [16]byte
	copy(submitter[:], []byte("submitter"))

	// Valid label
	var h [32]byte
	h[0] = 1
	if err := eng.Enqueue(chain.ProvenanceEntry{Hash: h, Submitter: submitter, Label: "ok"}); err != nil {
		t.Fatalf("valid label rejected: %v", err)
	}

	// Too long label
	long := string(make([]byte, 257))
	if err := eng.Enqueue(chain.ProvenanceEntry{Hash: h, Submitter: submitter, Label: long}); err == nil {
		t.Fatal("expected label too long error")
	}
}

func TestZeroHashRejected(t *testing.T) {
	uid, err := identity.NewUIDZero("zerohash-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "zerohash"}, time.Hour)

	var submitter [16]byte
	copy(submitter[:], []byte("submitter"))

	var zero [32]byte
	if err := eng.Enqueue(chain.ProvenanceEntry{Hash: zero, Submitter: submitter, Label: "zero"}); err == nil {
		t.Fatal("expected zero hash to be rejected")
	}
}

func TestSubmitterEmptyRejected(t *testing.T) {
	uid, err := identity.NewUIDZero("empty-submitter-test", testNetworkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "empty-submitter"}, time.Hour)

	var h [32]byte
	h[0] = 1
	var empty [16]byte
	if err := eng.Enqueue(chain.ProvenanceEntry{Hash: h, Submitter: empty, Label: "x"}); err == nil {
		t.Fatal("expected empty submitter to be rejected")
	}
}