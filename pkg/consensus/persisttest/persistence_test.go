//nolint:errcheck // test assertions
package persisttest

import (
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/storage"
)

func TestEnginePersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gleipnir-persist-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/engine.db"

	var networkID [32]byte
	copy(networkID[:], []byte("persist-test-network"))
	uid, err := identity.NewUIDZero("persist-test", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	node := consensus.Node{UID: *uid, Addr: "persist-test"}

	// Create storage
	st, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Create engine with storage
	eng := consensus.NewEngine(node, time.Hour)
	eng.SetStorage(st)

	// Submit some entries
	for i := 0; i < 5; i++ {
		hash := sha256.Sum256([]byte("entry"))
		hash[0] = byte(i + 1)
		var submitter [16]byte
		copy(submitter[:], uid.RootID[:])
		if err := eng.Enqueue(chain.ProvenanceEntry{
			Hash:      hash,
			Submitter: submitter,
			Label:     "test",
		}); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	// Run cycle
	eng.RunCycle()

	// Verify block created
	if eng.BlockCount() != 1 {
		t.Fatalf("expected 1 block, got %d", eng.BlockCount())
	}

	// Stop and restart engine
	eng.Stop()

	// Create new engine with same storage
	eng2 := consensus.NewEngine(node, time.Hour)
	eng2.SetStorage(st)

	// Verify state restored
	if eng2.BlockCount() != 1 {
		t.Fatalf("expected 1 block after restore, got %d", eng2.BlockCount())
	}

	block := eng2.GetBlock(0)
	if block == nil {
		t.Fatal("block 0 not found")
	}
	if len(block.Anchored) != 5 {
		t.Fatalf("expected 5 anchored entries, got %d", len(block.Anchored))
	}
}

func TestStatePersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gleipnir-state-persist-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/engine.db"

	var networkID [32]byte
	copy(networkID[:], []byte("state-persist-network"))
	uid, err := identity.NewUIDZero("state-test", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	node := consensus.Node{UID: *uid, Addr: "state-test"}

	st, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	eng := consensus.NewEngine(node, time.Hour)
	eng.SetStorage(st)

	// Run a few cycles to advance state
	for i := 0; i < 3; i++ {
		eng.RunCycle()
	}

	originalCycle := eng.Cycle()
	originalLambda1 := eng.GetHealth().Lambda1
	eng.Stop()

	// Restore
	eng2 := consensus.NewEngine(node, time.Hour)
	eng2.SetStorage(st)

	if eng2.Cycle() != originalCycle {
		t.Fatalf("cycle mismatch: expected %d, got %d", originalCycle, eng2.Cycle())
	}
	if eng2.GetHealth().Lambda1 != originalLambda1 {
		t.Fatalf("lambda1 mismatch: expected %f, got %f", originalLambda1, eng2.GetHealth().Lambda1)
	}
}

func TestSMTAndAnchoredPersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gleipnir-smt-persist-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/engine.db"

	var networkID [32]byte
	copy(networkID[:], []byte("smt-persist-network"))
	uid, err := identity.NewUIDZero("smt-test", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	node := consensus.Node{UID: *uid, Addr: "smt-test"}

	st, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	eng := consensus.NewEngine(node, time.Hour)
	eng.SetStorage(st)

	// Submit entries
	for i := 0; i < 3; i++ {
		hash := sha256.Sum256([]byte("anchor-entry"))
		hash[0] = byte(i + 1)
		var submitter [16]byte
		copy(submitter[:], uid.RootID[:])
		if err := eng.Enqueue(chain.ProvenanceEntry{
			Hash:      hash,
			Submitter: submitter,
			Label:     "smt-test",
		}); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	eng.RunCycle()

	// Verify anchor proofs accessible
	if eng.PendingCount() != 0 {
		t.Fatalf("expected 0 pending after cycle, got %d", eng.PendingCount())
	}

	block := eng.GetBlock(0)
	if block == nil {
		t.Fatal("no block found")
	}

	// Check SMT and anchored data
	for _, entry := range block.Anchored {
		proof, found := eng.LookupHash(entry.Hash)
		if !found {
			t.Fatalf("anchor proof not found for hash %x", entry.Hash)
		}
		if proof.BlockIndex != 0 {
			t.Fatalf("wrong block index in proof: expected 0, got %d", proof.BlockIndex)
		}
	}

	eng.Stop()

	// Restore and verify
	eng2 := consensus.NewEngine(node, time.Hour)
	eng2.SetStorage(st)

	for _, entry := range block.Anchored {
		proof, found := eng2.LookupHash(entry.Hash)
		if !found {
			t.Fatalf("anchor proof not found after restore for hash %x", entry.Hash)
		}
		if proof.BlockIndex != 0 {
			t.Fatalf("wrong block index after restore: expected 0, got %d", proof.BlockIndex)
		}
		if len(proof.SMTProof) == 0 {
			t.Fatal("SMT proof is empty after restore")
		}
	}
}