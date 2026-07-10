//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/smt"
)

func hashLen() int { return 32 }

func proofBytesToChunks(flat []byte) [][32]byte {
	n := len(flat) / 32
	chunks := make([][32]byte, n)
	for i := 0; i < n; i++ {
		copy(chunks[i][:], flat[i*32:(i+1)*32])
	}
	return chunks
}

func TestEmbeddedSubmitAnchorVerify(t *testing.T) {
	uid := identity.NewUIDZero("test-integration", true)
	node := consensus.Node{UID: *uid, Addr: "test-integration"}
	eng := consensus.NewEngine(node, 50*time.Millisecond)
	eng.Start()
	defer eng.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("artifact-v1.0.0"))
	if _, err := eng.Submit(ctx, hash, uid.RootID, "test-artifact"); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	proof, err := eng.WaitForAnchor(ctx, hash)
	if err != nil {
		t.Fatalf("WaitForAnchor: %v", err)
	}
	if !proof.Found {
		t.Fatal("proof.Found should be true")
	}
	// First block has index 0; verify it's monotonic in subsequent cycles
	if proof.BlockTime == 0 {
		t.Fatal("BlockTime should be set")
	}
	if proof.BlockTime == 0 {
		t.Fatal("BlockTime should be set")
	}
	// Proof may be empty for a single-entry tree (root = leaf hash).
	// Non-empty proofs are verified by reconstructing sibling hashes.

	var stateRootArr [32]byte
	copy(stateRootArr[:], proof.StateRoot)
	proofChunks := proofBytesToChunks(proof.SMTProof)

	st := smt.New(256)
	if !st.Verify(hash[:], hash[:], stateRootArr, proofChunks) {
		t.Fatal("SMT proof does not verify against StateRoot")
	}

	health, err := eng.GetNetworkHealth(ctx)
	if err != nil {
		t.Fatalf("GetNetworkHealth: %v", err)
	}
	t.Logf("BlockHeight=%d, Pending=%d, Active=%d, λ₁=%.4f",
		health.BlockHeight, health.PendingHashes, health.ActivePeers, health.Lambda1)
}

func TestEmbeddedVerifyNonexistent(t *testing.T) {
	uid := identity.NewUIDZero("test-verify-nonexistent", true)
	node := consensus.Node{UID: *uid, Addr: "test-verify-nonexistent"}
	eng := consensus.NewEngine(node, 50*time.Millisecond)
	eng.Start()
	defer eng.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("nonexistent"))
	_, err := eng.VerifyHash(ctx, hash)
	if err == nil {
		t.Fatal("expected error for nonexistent hash")
	}
}

func TestAnchorerInterface(t *testing.T) {
	uid := identity.NewUIDZero("test-anchorer-interface", true)
	node := consensus.Node{UID: *uid, Addr: "test-anchorer-interface"}
	eng := consensus.NewEngine(node, 50*time.Millisecond)
	eng.Start()
	defer eng.Close()

	var anchorer chain.Anchorer = eng
	if anchorer == nil {
		t.Fatal("Engine should implement Anchorer")
	}
}
