//nolint:errcheck // test assertions
package consensus

import (
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/state"
)

// --- D01: Livelock regression — fragmentation/recovery cycle ---
func TestLivelockRegressionFragmentationRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping livelock regression in short mode")
	}

	var networkID [32]byte
	copy(networkID[:], []byte("livelock-test-network"))
	uid, err := identity.NewUIDZero("livelock-test", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(Node{UID: *uid, Addr: "livelock-test"}, time.Hour)

	// Add a second peer but keep it disconnected (no shared edges)
	// → λ₁ = 0 for a 2-node graph with no edges
	peer2, err := identity.NewUIDZero("livelock-peer2", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	eng.state.Nodes[peer2.ID()] = state.NodeState{
		UID:    peer2.RootID,
		Status: 1.0,
	}
	// Disconnect the graph: keep only the self-loop
	eng.state.Graph.Edges = []state.Edge{
		{From: uid.ID(), To: uid.ID(), Weight: 1.0},
	}

	eng.cfg.MinLambda1 = 0.5 // forces fragmentation (λ₁ = 0 with no cross-edges)

	// Run 10 cycles — none should produce a block
	for i := 0; i < 10; i++ {
		var submitter [16]byte
		copy(submitter[:], uid.RootID[:])
		eng.Enqueue(chain.ProvenanceEntry{Hash: [32]byte{byte(i + 1)}, Submitter: submitter})
		eng.RunCycle()
	}

	if len(eng.blocks) != 0 {
		t.Fatalf("expected 0 blocks during fragmentation window, got %d", len(eng.blocks))
	}
	if eng.state.Cycle != 10 {
		t.Fatalf("expected cycle to advance to 10 during fragmentation, got %d", eng.state.Cycle)
	}

	// Recovery: connect the graph with edges between both nodes
	eng.state.Graph.Edges = []state.Edge{
		{From: uid.ID(), To: peer2.ID(), Weight: 1.0},
		{From: peer2.ID(), To: uid.ID(), Weight: 1.0},
	}
	// Also lower MinLambda1 to a reachable value
	eng.cfg.MinLambda1 = 0.1

	// Run more cycles — blocks should resume
	for i := 0; i < 5; i++ {
		var submitter [16]byte
		copy(submitter[:], uid.RootID[:])
		eng.Enqueue(chain.ProvenanceEntry{Hash: [32]byte{byte(100 + i)}, Submitter: submitter})
		eng.RunCycle()
	}

	if len(eng.blocks) != 5 {
		t.Fatalf("expected 5 blocks after recovery, got %d", len(eng.blocks))
	}
	if eng.state.Cycle != 15 {
		t.Fatalf("expected cycle 15, got %d", eng.state.Cycle)
	}

	t.Logf("Livelock regression: fragmentation → %d cycles, 0 blocks", 10)
	t.Logf("Recovery → %d cycles, %d blocks", 5, len(eng.blocks))
}