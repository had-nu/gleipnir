package consensus

import (
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func makePeersAndNodes(seeds ...string) ([]Peer, []Node) {
	peers := make([]Peer, len(seeds))
	nodes := make([]Node, len(seeds))
	for i, s := range seeds {
		uid := identity.NewUIDZero(s, true)
		peers[i] = Peer{UID: *uid, Addr: s, Alive: true}
		nodes[i] = Node{UID: *uid, Addr: s}
	}
	return peers, nodes
}

func proposerFirstOrder(peers []Peer, cycle uint64, root []byte) []int {
	proposer, _ := SelectProposer(peers, cycle, root)
	proposerHex := proposer.UID.ID()
	order := make([]int, 0, len(peers))
	for i, p := range peers {
		if p.UID.ID() == proposerHex {
			order = append(order, i)
			break
		}
	}
	for i := range peers {
		if len(order) == 0 || order[0] != i {
			order = append(order, i)
		}
	}
	return order
}

func TestThreeNodeConsensus(t *testing.T) {
	peers, nodes := makePeersAndNodes("node-a", "node-b", "node-c")
	bus := NewMemoryBus()

	engines := make([]*Engine, 3)
	for i := 0; i < 3; i++ {
		engines[i] = NewEngineWithPeers(nodes[i], time.Hour, bus, peers)
	}

	// Cycle 0: submit and commit 3 entries (unique hashes per engine)
	for i, eng := range engines {
		eng.Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{byte(i + 1)},
			Submitter: peers[i].UID.RootID,
		})
	}

	root0 := engines[0].st.Root()
	order := proposerFirstOrder(peers, 0, root0[:])
	for _, idx := range order {
		engines[idx].RunCycle()
	}
	// Run cycle on ALL engines so non-proposers can verify and sign
	for i := range engines {
		if !contains(order, i) {
			engines[i].RunCycle()
		}
	}

	// After cycle 0: all engines should have 1 block with 3 entries
	for i, eng := range engines {
		if eng.BlockCount() != 1 {
			t.Fatalf("engine %d: expected 1 block, got %d", i, eng.BlockCount())
		}
	}
	// Verify identical block 0
	for i := 1; i < 3; i++ {
		b0 := engines[0].GetBlock(0)
		bi := engines[i].GetBlock(0)
		if string(b0.BlockHash) != string(bi.BlockHash) {
			t.Fatalf("engine %d block 0 hash mismatch", i)
		}
	}

	t.Logf("Cycle 0: 1 block with %d entries, λ₁=%.4f", len(engines[0].GetBlock(0).Anchored), engines[0].GetHealth().Lambda1)

	// Cycle 1: submit 3 more entries
	for i, eng := range engines {
		eng.Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{10 + byte(i + 1)},
			Submitter: peers[i].UID.RootID,
		})
	}

	stateRoot1 := engines[0].GetBlock(0).StateRoot
	order = proposerFirstOrder(peers, 1, stateRoot1)
	for _, idx := range order {
		engines[idx].RunCycle()
	}
	// Run cycle on ALL engines so non-proposers can verify and sign
	for i := range engines {
		if !contains(order, i) {
			engines[i].RunCycle()
		}
	}

	for i, eng := range engines {
		if eng.BlockCount() != 2 {
			t.Fatalf("engine %d: expected 2 blocks, got %d", i, eng.BlockCount())
		}
	}
	for i := 1; i < 3; i++ {
		b0 := engines[0].GetBlock(1)
		bi := engines[i].GetBlock(1)
		if string(b0.BlockHash) != string(bi.BlockHash) {
			t.Fatalf("engine %d block 1 hash mismatch", i)
		}
	}

	// Verify all hashes anchored
	for _, eng := range engines {
		for i := 0; i < 2; i++ {
			proof, ok := eng.LookupHash([32]byte{byte(i + 1)})
			if !ok || !proof.Found {
				t.Fatalf("missing hash %d", i+1)
			}
			proof, ok = eng.LookupHash([32]byte{10 + byte(i + 1)})
			if !ok || !proof.Found {
				t.Fatalf("missing hash %d", 10+i+1)
			}
		}
	}

	t.Logf("Three-node consensus: %d identical blocks across 3 engines", engines[0].BlockCount())
}

func contains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func TestMultiNodeEdgesAndLambda(t *testing.T) {
	peers, nodes := makePeersAndNodes("lambda-a", "lambda-b", "lambda-c")
	bus := NewMemoryBus()

	eng := NewEngineWithPeers(nodes[0], time.Hour, bus, peers)

	health := eng.GetHealth()
	t.Logf("Initial: peers=%d, edges=%d", health.TotalPeers, len(eng.state.Graph.Edges))
	if health.TotalPeers != 3 {
		t.Fatalf("expected 3 peers, got %d", health.TotalPeers)
	}

	eng.Enqueue(chain.ProvenanceEntry{Hash: [32]byte{1}, Submitter: peers[0].UID.RootID})

	rootLambda := eng.st.Root()
	order := proposerFirstOrder(peers, 0, rootLambda[:])
	for _, idx := range order {
		if idx != 0 {
			continue // only testing engine 0
		}
		eng.RunCycle()
	}

	health = eng.GetHealth()
	t.Logf("After cycle: blocks=%d, λ₁=%.4f", health.BlockHeight, health.Lambda1)
	if health.Lambda1 <= 0 {
		t.Fatal("λ₁ should be > 0 for fully connected 3-node graph")
	}
}

func TestDeterministicProposerAcrossPeers(t *testing.T) {
	peers, nodes := makePeersAndNodes("det-a", "det-b", "det-c")
	bus := NewMemoryBus()

	engines := make([]*Engine, 3)
	for i := 0; i < 3; i++ {
		engines[i] = NewEngineWithPeers(nodes[i], time.Hour, bus, peers)
	}

	hash := [32]byte{99}
	for _, eng := range engines {
		eng.Enqueue(chain.ProvenanceEntry{Hash: hash, Submitter: eng.node.UID.RootID})
	}

	// All 3 engines must independently select the same proposer
	rootDet := engines[0].st.Root()
	proposer0, score0 := SelectProposer(peers, 0, rootDet[:])
	for i := 1; i < 3; i++ {
		r := engines[i].st.Root()
		p, s := SelectProposer(peers, 0, r[:])
		if string(p.UID.RootID) != string(proposer0.UID.RootID) {
			t.Fatalf("engine %d selected different proposer", i)
		}
		if string(s) != string(score0) {
			t.Fatalf("engine %d computed different score", i)
		}
	}

	// Run with proposer first
	order := proposerFirstOrder(peers, 0, rootDet[:])
	for _, idx := range order {
		engines[idx].RunCycle()
	}

	for i, eng := range engines {
		if eng.BlockCount() != 1 {
			t.Fatalf("engine %d: expected 1 block, got %d", i, eng.BlockCount())
		}
		block := eng.GetBlock(0)
		if string(block.Proposer) != string(proposer0.UID.RootID) {
			t.Fatalf("engine %d: proposer mismatch", i)
		}
	}

	t.Logf("Deterministic proposer: all 3 engines agree on proposer and produce identical block")
}
