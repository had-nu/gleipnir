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

// vrfProofsForPeers builds a VRF proofs map for the given peers.
func vrfProofsForPeers(peers []Peer, cycle uint64, stateRoot []byte) map[string]*identity.VRFProof {
	alpha := makeAlpha(cycle, stateRoot)
	proofs := make(map[string]*identity.VRFProof, len(peers))
	for _, p := range peers {
		proof, err := p.UID.VRFProve(alpha)
		if err != nil {
			panic("VRFProve failed in test helper: " + err.Error())
		}
		proofs[p.UID.ID()] = proof
	}
	return proofs
}

func TestSelectProposerDeterministic(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	proofs := vrfProofsForPeers(peers, 1, []byte("state1"))
	p1, s1, err1 := SelectProposer(peers, 1, []byte("state1"), proofs)
	p2, s2, err2 := SelectProposer(peers, 1, []byte("state1"), proofs)
	if err1 != nil || err2 != nil {
		t.Fatalf("SelectProposer failed: %v / %v", err1, err2)
	}

	if p1.Addr != p2.Addr {
		t.Fatalf("same cycle+state should select same proposer: %s vs %s", p1.Addr, p2.Addr)
	}
	if !testEq(s1.Gamma, s2.Gamma) {
		t.Fatal("VRF outputs should match for same inputs")
	}
}

func TestSelectProposerChangesWithCycle(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	p1, _, err := SelectProposer(peers, 0, []byte("state"), vrfProofsForPeers(peers, 0, []byte("state")))
	if err != nil {
		t.Fatalf("SelectProposer failed: %v", err)
	}
	p2, _, err := SelectProposer(peers, 1, []byte("state"), vrfProofsForPeers(peers, 1, []byte("state")))
	if err != nil {
		t.Fatalf("SelectProposer failed: %v", err)
	}

	if p1.Addr == p2.Addr {
		t.Log("same proposer for different cycles is possible but unlikely for 3 peers")
	}
}

func TestSelectProposerChangesWithState(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	p1, _, err := SelectProposer(peers, 0, []byte("state-a"), vrfProofsForPeers(peers, 0, []byte("state-a")))
	if err != nil {
		t.Fatalf("SelectProposer failed: %v", err)
	}
	p2, _, err := SelectProposer(peers, 0, []byte("state-b"), vrfProofsForPeers(peers, 0, []byte("state-b")))
	if err != nil {
		t.Fatalf("SelectProposer failed: %v", err)
	}

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

	var pks [][]byte
	var sks [][]byte
	for i := 0; i < 3; i++ {
		pk, sk, err := identity.GenerateDilithiumKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pk)
		sks = append(sks, sk)
	}

	var sigs [][]byte
	for i := 0; i < 3; i++ {
		sigs = append(sigs, identity.SignDilithium(sks[i], msg))
	}

	quorum := chain.DefaultQuorumConfig()
	err := VerifyQuorum(msg, sigs, pks, quorum)
	if err != nil {
		t.Fatalf("quorum should pass: %v", err)
	}

	// Test: signature from a NON-validator should be rejected
	_, skOther, _ := identity.GenerateDilithiumKey(rand.Reader)
	badSig := identity.SignDilithium(skOther, msg)
	badSigs := make([][]byte, len(sigs))
	copy(badSigs, sigs)
	badSigs[0] = badSig

	err = VerifyQuorum(msg, badSigs, pks, quorum)
	if err == nil {
		t.Fatal("quorum should fail with signature from non-validator")
	}

	// Test: fewer than RequiredSigs valid signatures should fail
	tooFewSigs := sigs[:2] // only 2 valid sigs, need 3
	err = VerifyQuorum(msg, tooFewSigs, pks, quorum)
	if err == nil {
		t.Fatal("quorum should fail with too few valid signatures")
	}

	// Test: duplicate signatures from the same signer should NOT satisfy M-of-N
	dupSigs := make([][]byte, 3)
	for i := range dupSigs {
		dupSigs[i] = sigs[0]
	}
	err = VerifyQuorum(msg, dupSigs, pks, quorum)
	if err == nil {
		t.Fatal("quorum should reject duplicate signatures from a single signer")
	}

	// Test: duplicate signatures below threshold (1 distinct signer for 2/3)
	q2 := chain.QuorumConfig{TotalValidators: 3, RequiredSigs: 2}
	err = VerifyQuorum(msg, dupSigs, pks, q2)
	if err == nil {
		t.Fatal("1 distinct signer should not satisfy even a 2-of-3 quorum")
	}

	// Test: validator set pinning — VerifyQuorum rejects when pubKeys don't match block.Validators
	// (The caller must supply the block's own recorded Validators field, not an attacker-chosen set.)
	pkEvil, skEvil, _ := identity.GenerateDilithiumKey(rand.Reader)
	evilSig := identity.SignDilithium(skEvil, msg)
	evilPks := [][]byte{pkEvil}       // attacker supplies their own "validator set"
	err = VerifyQuorum(msg, [][]byte{evilSig}, evilPks,
		chain.QuorumConfig{TotalValidators: 1, RequiredSigs: 1})
	if err != nil {
		t.Fatal("VerifyQuorum itself accepts any pubKeys — pinning must be enforced by the caller")
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
	if len(last.Sigs) == 0 || len(last.Sigs[0]) == 0 {
		t.Error("Sigs must be populated (single signature)")
	}
	// In single-node mode, we expect exactly 1 signature
	if len(last.Sigs) != 1 {
		t.Errorf("expected exactly 1 signature in single-node mode, got %d", len(last.Sigs))
	}
}
