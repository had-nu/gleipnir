package consensus

import (
	"bytes"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

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
		{Hash: [32]byte{1}, Submitter: []byte("alice"), Label: "a"},
		{Hash: [32]byte{2}, Submitter: []byte("bob"), Label: "b"},
	}

	// Same identity seed for both engines — simulated=true makes it deterministic
	uid := identity.NewUIDZero("determinism-test", true)

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

	uid := identity.NewUIDZero("race-node", true)
	eng := NewEngine(Node{UID: *uid, Addr: "race-node"}, time.Hour)
	eng.nowFunc = fixedClock(refTime)

	const n = 10
	var wg sync.WaitGroup
	for i := byte(0); i < n; i++ {
		wg.Add(1)
		go func(h byte) {
			defer wg.Done()
			eng.Enqueue(chain.ProvenanceEntry{Hash: [32]byte{h + 1}, Submitter: []byte("t"), Label: "r"})
		}(i)
	}
	wg.Wait()

	eng.RunCycle()

	eng.mu.Lock()
	defer eng.mu.Unlock()
	if len(eng.blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(eng.blocks))
	}
	if len(eng.blocks[0].Anchored) != n {
		t.Fatalf("expected %d entries anchored, got %d", n, len(eng.blocks[0].Anchored))
	}
}

// --- A03: Block-chain tamper detection ---

func TestBlockChainTamperDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chain-length test in short mode")
	}

	uid := identity.NewUIDZero("chain-test", true)
	eng := NewEngine(Node{UID: *uid, Addr: "chain-test"}, time.Hour)
	refTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eng.nowFunc = fixedClock(refTime)

	const nBlocks = 50
	for i := 0; i < nBlocks; i++ {
		eng.Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{byte(i + 1)},
			Submitter: []byte("t"),
			Label:     strings.Repeat("x", 10),
		})
		eng.RunCycle()
	}

	eng.mu.Lock()
	if len(eng.blocks) != nBlocks {
		t.Fatalf("expected %d blocks, got %d", nBlocks, len(eng.blocks))
	}

	origBlockHash := make([]byte, len(eng.blocks[25].BlockHash))
	copy(origBlockHash, eng.blocks[25].BlockHash)

	origStateRoot := make([]byte, len(eng.blocks[25].StateRoot))
	copy(origStateRoot, eng.blocks[25].StateRoot)

	// Mutate: change the block's timestamp
	eng.blocks[25].Timestamp = 999999
	eng.mu.Unlock()

	// Walk chain and verify integrity
	eng.mu.Lock()
	mismatchIdx := checkChainIntegrity(eng.blocks)
	eng.mu.Unlock()

	if mismatchIdx < 0 {
		t.Fatal("expected chain integrity check to detect mutation at block 25, but no mismatch found")
	}
	if mismatchIdx != 25 {
		t.Fatalf("expected mismatch at block 25, reported at %d", mismatchIdx)
	}

	_ = origBlockHash
	_ = origStateRoot
}

func checkChainIntegrity(blocks []chain.Block) int {
	for i, b := range blocks {
		var expectedPrev []byte
		if i == 0 {
			expectedPrev = make([]byte, 32)
		} else {
			expectedPrev = blocks[i-1].BlockHash
		}
		if !bytes.Equal(b.PrevHash, expectedPrev) {
			return i
		}

		computed := computeBlockHash(b)
		if !bytes.Equal(computed, b.BlockHash) {
			return i
		}
	}
	return -1
}

// --- B02: Signature non-malleability ---

func TestSignatureNonMalleability(t *testing.T) {
	uid := identity.NewUIDZero("nonmalle", true)
	block := chain.Block{
		Index:     0,
		PrevHash:  make([]byte, 32),
		Proposer:  uid.RootID,
		StateRoot: make([]byte, 32),
		Anchored:  []chain.ProvenanceEntry{{Hash: [32]byte{42}}},
		Timestamp: 1000,
	}

	hash := computeBlockHash(block)
	sig1 := identity.SignDilithium(uid.SecretKey, hash)
	sig2 := identity.SignDilithium(uid.SecretKey, hash)

	blockWithSig1 := block
	blockWithSig1.Sigs[0] = sig1
	blockWithSig1.BlockHash = hash

	blockWithSig2 := block
	blockWithSig2.Sigs[0] = sig2
	blockWithSig2.BlockHash = hash

	h1 := computeBlockHash(blockWithSig1)
	h2 := computeBlockHash(blockWithSig2)
	if !bytes.Equal(h1, h2) {
		t.Fatal("BlockHash changed when a different valid signature from the same key was attached")
	}
	if !bytes.Equal(h1, hash) {
		t.Fatal("BlockHash changed after attaching any signature")
	}
}

// --- B03: Forged signature rejection ---

func TestForgedSignatureRejection(t *testing.T) {
	msg := []byte("test block hash")

	pkA, skA, err := identity.GenerateDilithiumKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, skB, err := identity.GenerateDilithiumKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sigA := identity.SignDilithium(skA, msg)
	sigB := identity.SignDilithium(skB, msg)

	// Valid quorum with 3 A-sigs
	err = VerifyQuorum(msg, [3][]byte{sigA, sigA, sigA}, [3][]byte{pkA, pkA, pkA})
	if err != nil {
		t.Fatalf("expected valid quorum to pass: %v", err)
	}

	// Forged: sig from key B replaces one A-sig
	err = VerifyQuorum(msg, [3][]byte{sigA, sigB, sigA}, [3][]byte{pkA, pkA, pkA})
	if err == nil {
		t.Fatal("expected forged signature (valid sig from wrong key) to be rejected")
	}
}
