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
	// Create temp dir for BoltDB
	tmpDir, err := os.MkdirTemp("", "gleipnir-persist-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/engine.db"

	uid := identity.NewUIDZero("persist-test", true)
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
		if err := eng.Enqueue(chain.ProvenanceEntry{
			Hash:      hash,
			Submitter: uid.RootID,
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
		t.Fatalf("after restart: expected 1 block, got %d", eng2.BlockCount())
	}

	// Verify anchored proof exists
	hash := sha256.Sum256([]byte("entry"))
	hash[0] = 1 // first entry
	proof, ok := eng2.LookupHash(hash)
	if !ok || !proof.Found {
		t.Fatal("anchored proof not found after restart")
	}

	// Verify state cycle advanced
	if eng2.Cycle() != 1 {
		t.Fatalf("cycle not restored: got %d", eng2.Cycle())
	}
}

func TestEnginePersistenceMultipleCycles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gleipnir-persist-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/engine.db"

	uid := identity.NewUIDZero("persist-multi", true)
	node := consensus.Node{UID: *uid, Addr: "persist-multi"}

	st, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	eng := consensus.NewEngine(node, time.Hour)
	eng.SetStorage(st)

	// Run multiple cycles
	for cycle := 0; cycle < 3; cycle++ {
		for i := 0; i < 2; i++ {
			hash := sha256.Sum256([]byte("multi"))
			hash[0] = byte(cycle*10 + i + 1)
			if err := eng.Enqueue(chain.ProvenanceEntry{
				Hash:      hash,
				Submitter: uid.RootID,
				Label:     "multi",
			}); err != nil {
				t.Fatalf("Enqueue cycle %d entry %d: %v", cycle, i, err)
			}
		}
		eng.RunCycle()
	}

	if eng.BlockCount() != 3 {
		t.Fatalf("expected 3 blocks, got %d", eng.BlockCount())
	}

	eng.Stop()

	// Restart and verify all blocks
	eng2 := consensus.NewEngine(node, time.Hour)
	eng2.SetStorage(st)

	if eng2.BlockCount() != 3 {
		t.Fatalf("after restart: expected 3 blocks, got %d", eng2.BlockCount())
	}

	// Verify all anchored proofs
	for cycle := 0; cycle < 3; cycle++ {
		for i := 0; i < 2; i++ {
			hash := sha256.Sum256([]byte("multi"))
			hash[0] = byte(cycle*10 + i + 1)
			proof, ok := eng2.LookupHash(hash)
			if !ok || !proof.Found {
				t.Fatalf("proof not found for cycle %d entry %d", cycle, i)
			}
		}
	}
}

func TestEnginePersistenceSMT(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gleipnir-smt-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/engine.db"

	uid := identity.NewUIDZero("smt-test", true)
	node := consensus.Node{UID: *uid, Addr: "smt-test"}

	st, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	eng := consensus.NewEngine(node, time.Hour)
	eng.SetStorage(st)

	// Submit entries that will be in SMT
	hashes := make([][32]byte, 10)
	for i := 0; i < 10; i++ {
		h := sha256.Sum256([]byte("smt-entry"))
		h[0] = byte(i + 1)
		hashes[i] = h
		eng.Enqueue(chain.ProvenanceEntry{
			Hash:      h,
			Submitter: uid.RootID,
			Label:     "smt",
		})
	}

	eng.RunCycle()

	// Get SMT root
	root1 := eng.GetStateRoot()

	eng.Stop()

	// Restart
	eng2 := consensus.NewEngine(node, time.Hour)
	eng2.SetStorage(st)

	root2 := eng2.GetStateRoot()

	if string(root1) != string(root2) {
		t.Fatalf("SMT root mismatch after restart: %x vs %x", root1, root2)
	}

	// Verify SMT proofs work
	for _, h := range hashes {
		proof, err := eng2.ProveSMT(h[:])
		if err != nil {
			t.Fatalf("ProveSMT failed: %v", err)
		}
		if len(proof) == 0 {
			t.Fatal("empty SMT proof")
		}
	}
}

func TestEnginePersistencePendingEntries(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gleipnir-pending-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/engine.db"

	uid := identity.NewUIDZero("pending-test", true)
	node := consensus.Node{UID: *uid, Addr: "pending-test"}

	st, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	eng := consensus.NewEngine(node, time.Hour)
	eng.SetStorage(st)

	// Add pending entries but don't run cycle
	for i := 0; i < 3; i++ {
		hash := sha256.Sum256([]byte("pending"))
		hash[0] = byte(i + 1)
		eng.Enqueue(chain.ProvenanceEntry{
			Hash:      hash,
			Submitter: uid.RootID,
			Label:     "pending",
		})
	}

	pendingBefore := eng.PendingCount()
	if pendingBefore != 3 {
		t.Fatalf("expected 3 pending, got %d", pendingBefore)
	}

	eng.Stop()

	// Restart
	eng2 := consensus.NewEngine(node, time.Hour)
	eng2.SetStorage(st)

	pendingAfter := eng2.PendingCount()
	if pendingAfter != 3 {
		t.Fatalf("after restart: expected 3 pending, got %d", pendingAfter)
	}

	// Now run cycle - should use pending entries
	eng2.RunCycle()

	if eng2.BlockCount() != 1 {
		t.Fatalf("expected 1 block after cycle, got %d", eng2.BlockCount())
	}
}