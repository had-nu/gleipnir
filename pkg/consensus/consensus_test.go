package consensus

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/state"
)

func testPeer(id string) Peer {
	uid := identity.NewUIDZero("test-"+id, true)
	return Peer{UID: *uid, Addr: id, Alive: true}
}

func TestSelectProposerDeterministic(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	p1, s1 := SelectProposer(peers, 1, []byte("state1"))
	p2, s2 := SelectProposer(peers, 1, []byte("state1"))

	if p1.Addr != p2.Addr {
		t.Fatalf("same cycle+state should select same proposer: %s vs %s", p1.Addr, p2.Addr)
	}
	if !testEq(s1, s2) {
		t.Fatal("scores should match for same inputs")
	}
}

func TestSelectProposerChangesWithCycle(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	p1, _ := SelectProposer(peers, 0, []byte("state"))
	p2, _ := SelectProposer(peers, 1, []byte("state"))

	if p1.Addr == p2.Addr {
		t.Log("same proposer for different cycles is possible but unlikely for 3 peers")
	}
}

func TestSelectProposerChangesWithState(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	p1, _ := SelectProposer(peers, 0, []byte("state-a"))
	p2, _ := SelectProposer(peers, 0, []byte("state-b"))

	if p1.Addr == p2.Addr {
		t.Log("same proposer for different state roots is possible but unlikely for 3 peers")
	}
}

func TestSelectTriad(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	triad := SelectTriad(peers, 0, 3)
	if len(triad) != 3 {
		t.Fatalf("triad should have 3 members, got %d", len(triad))
	}
	if len(triad[0]) == 0 || len(triad[1]) == 0 || len(triad[2]) == 0 {
		t.Fatal("triad members should have non-empty UID slices")
	}
}

func TestVerifyQuorum(t *testing.T) {
	msg := []byte("test block hash")

	var pks [3][]byte
	var sks [3][]byte
	for i := 0; i < 3; i++ {
		pk, sk, err := identity.GenerateDilithiumKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pks[i] = pk
		sks[i] = sk
	}

	var sigs [3][]byte
	for i := 0; i < 3; i++ {
		sigs[i] = identity.SignDilithium(sks[i], msg)
	}

	err := VerifyQuorum(msg, sigs, pks)
	if err != nil {
		t.Fatalf("quorum should pass: %v", err)
	}

	wrongSigs := sigs
	wrongSigs[0] = sigs[1]

	err = VerifyQuorum(msg, wrongSigs, pks)
	if err == nil {
		t.Fatal("quorum should fail with wrong signature")
	}
}

func TestVerifyQuorumWrongKey(t *testing.T) {
	msg := []byte("test")
	_, sk, _ := identity.GenerateDilithiumKey(rand.Reader)
	pk2, _, _ := identity.GenerateDilithiumKey(rand.Reader)

	sig := identity.SignDilithium(sk, msg)

	err := VerifyQuorum(msg, [3][]byte{sig, sig, sig}, [3][]byte{pk2, pk2, pk2})
	if err == nil {
		t.Fatal("quorum should fail with wrong public key")
	}
}

func testEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- P1: cycle advancement tests ---

func newTestEngine() *Engine {
	uid := identity.NewUIDZero("test-self", true)
	node := Node{UID: *uid, Addr: "self"}
	eng := NewEngine(node, time.Hour)
	uidHex := uid.ID()
	eng.state.Nodes[uidHex] = state.NodeState{
		UID:    uid.RootID,
		Status: 1.0,
	}
	return eng
}

func addEdgesForNodes(eng *Engine) {
	uids := make([]string, 0, len(eng.state.Nodes))
	for uid := range eng.state.Nodes {
		uids = append(uids, uid)
	}
	for i := 0; i < len(uids); i++ {
		for j := i + 1; j < len(uids); j++ {
			eng.state.Graph.Edges = append(eng.state.Graph.Edges, state.Edge{
				From:   uids[i],
				To:     uids[j],
				Weight: 1.0,
			})
		}
	}
}

func addPending(eng *Engine) {
	eng.pending = append(eng.pending, chain.ProvenanceEntry{
		Hash: [32]byte{1},
	})
}

func addDisconnectedPeer(eng *Engine) {
	peer2 := testPeer("disc-peer2")
	eng.state.Nodes[peer2.UID.ID()] = state.NodeState{
		UID:    peer2.UID.RootID,
		Status: 1.0,
	}
}

func TestCycleAdvancesOnFragmentation(t *testing.T) {
	eng := newTestEngine()
	addDisconnectedPeer(eng)     // 2 nodes, no edges between them → λ₁ = 0
	eng.cfg.MinLambda1 = 0.5     // 0 < 0.5 → always fragmented
	addPending(eng)

	prevCycle := eng.state.Cycle
	prevBlocks := len(eng.blocks)

	eng.RunCycle()

	if eng.state.Cycle != prevCycle+1 {
		t.Fatalf("expected cycle %d, got %d (must advance on fragmentation)", prevCycle+1, eng.state.Cycle)
	}
	if len(eng.blocks) != prevBlocks {
		t.Fatalf("expected %d blocks (no append on fragmentation), got %d", prevBlocks, len(eng.blocks))
	}

	eng.RunCycle()
	if eng.state.Cycle != prevCycle+2 {
		t.Fatalf("expected cycle %d after second call, got %d", prevCycle+2, eng.state.Cycle)
	}
	if len(eng.blocks) != prevBlocks {
		t.Fatalf("blocks should not advance across repeated fragmentation")
	}
}

func TestRunCycleAlwaysAdvancesCycle(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(eng *Engine)
		wantBlock  bool
		desc       string
	}{
		{
			name: "no pending entries",
			setup: func(eng *Engine) {
			},
			wantBlock: false,
			desc:      "early return with cycle increment when pending is empty",
		},
		{
			name: "inactive proposer",
			setup: func(eng *Engine) {
				addPending(eng)
				uidHex := eng.node.UID.ID()
				eng.state.Nodes[uidHex] = state.NodeState{
					UID:    eng.node.UID.RootID,
					Status: 0,
				}
			},
			wantBlock: false,
			desc:      "early return with cycle increment when proposer status <= 0",
		},
		{
			name: "fragmentation error",
			setup: func(eng *Engine) {
				addPending(eng)
				addDisconnectedPeer(eng) // 2 nodes, no edges
				eng.cfg.MinLambda1 = 0.5
			},
			wantBlock: false,
			desc:      "early return with cycle increment on Apply fragmentation error",
		},
		{
			name: "happy path",
			setup: func(eng *Engine) {
				addPending(eng)
				uidHex := eng.node.UID.ID()
				eng.state.Nodes[uidHex] = state.NodeState{
					UID:    eng.node.UID.RootID,
					Status: 1.0,
				}
				// Add second peer so Laplacian has ≥2 nodes
				peer2 := testPeer("peer2")
				eng.state.Nodes[peer2.UID.ID()] = state.NodeState{
					UID:    peer2.UID.RootID,
					Status: 1.0,
				}
				addEdgesForNodes(eng)
			},
			wantBlock: true,
			desc:      "block appended on successful Apply",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTestEngine()
			tt.setup(eng)

			prevCycle := eng.state.Cycle
			prevBlocks := len(eng.blocks)

			eng.RunCycle()

			if eng.state.Cycle != prevCycle+1 {
				t.Fatalf("expected cycle %d, got %d: %s", prevCycle+1, eng.state.Cycle, tt.desc)
			}

			gotBlock := len(eng.blocks) > prevBlocks
			if gotBlock != tt.wantBlock {
				t.Fatalf("wantBlock=%v, got block append=%v: %s", tt.wantBlock, gotBlock, tt.desc)
			}

			if tt.wantBlock && len(eng.blocks) > 0 {
				last := eng.blocks[len(eng.blocks)-1]
				if !bytes.Equal(last.Proposer, eng.node.UID.RootID) {
					t.Errorf("block proposer mismatch: %s", tt.desc)
				}
			}
		})
	}
}

// --- P2: single-node run-cycle test ---

func TestSingleNodeRunCycle(t *testing.T) {
	eng := newTestEngine()
	addPending(eng)
	uidHex := eng.node.UID.ID()
	eng.state.Nodes[uidHex] = state.NodeState{
		UID:    eng.node.UID.RootID,
		Status: 1.0,
	}
	// Add a second node so Laplacian is non-trivial (λ₁ > MinLambda1)
	peer2 := testPeer("peer2")
	eng.state.Nodes[peer2.UID.ID()] = state.NodeState{
		UID:    peer2.UID.RootID,
		Status: 1.0,
	}
	addEdgesForNodes(eng)

	blocksBefore := len(eng.blocks)
	eng.RunCycle()

	if len(eng.blocks) != blocksBefore+1 {
		t.Fatalf("expected exactly one block appended, got %d blocks", len(eng.blocks))
	}

	last := eng.blocks[len(eng.blocks)-1]
	if len(last.Sigs[0]) == 0 {
		t.Error("Sigs[0] must be populated (single signature)")
	}
	for i := 1; i < 3; i++ {
		if len(last.Sigs[i]) != 0 {
			t.Errorf("Sigs[%d] must be empty in single-node mode, got %d bytes", i, len(last.Sigs[i]))
		}
	}
}
