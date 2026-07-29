//nolint:errcheck // test assertions
package consensus

import (
	"bytes"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func makePeersAndNodes(seeds ...string) ([]Peer, []Node) {
	peers := make([]Peer, len(seeds))
	nodes := make([]Node, len(seeds))
	var networkID [32]byte
	copy(networkID[:], []byte("multinode-test-network"))
	for i, s := range seeds {
		uid, err := identity.NewUIDZero(s, networkID, true)
		if err != nil {
			panic(err)
		}
		peers[i] = Peer{UID: *uid, Addr: s, Alive: true}
		nodes[i] = Node{UID: *uid, Addr: s}
	}
	return peers, nodes
}

func triadToIndices(peers []Peer, triad Triad) []int {
	indices := make([]int, 3)
	rootIDToIndex := make(map[[16]byte]int)
	for i, p := range peers {
		rootIDToIndex[p.UID.RootID] = i
	}
	for i, rootID := range triad {
		indices[i] = rootIDToIndex[rootID]
	}
	return indices
}

func TestMultiNodeConsensusDeterministic(t *testing.T) {
	peers, nodes := makePeersAndNodes("peer-0", "peer-1", "peer-2")
	bus := NewMemoryBus()

	engines := make([]*Engine, 3)
	for i := 0; i < 3; i++ {
		engines[i] = NewEngineWithPeers(nodes[i], time.Hour, bus, peers)
		engines[i].cfg.SkipEmptyCycles = false
		engines[i].cfg.MinLambda1 = 0.001 // Allow blocks even with λ₁=0
	}

	// Submit entries
	for i := 0; i < 3; i++ {
		engines[i].Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{byte(i + 1)},
			Submitter: peers[i].UID.RootID,
		})
	}

	// Run cycle 0
	var rootArr [32]byte
	var t2 [32]byte = engines[0].st.Root()
	copy(rootArr[:], t2[:])
	proposer, proof, _ := SelectProposer(peers, 0, rootArr[:], vrfProofsForPeers(peers, 0, rootArr[:]))
	_ = proposer
	_ = proof
	
	for _, idx := range []int{0, 1, 2} {
		engines[idx].RunCycle()
	}

	for i, eng := range engines {
		if eng.BlockCount() != 1 {
			t.Fatalf("engine %d: expected 1 block, got %d", i, eng.BlockCount())
		}
	}

	for i := 1; i < 3; i++ {
		b0 := engines[0].GetBlock(0)
		bi := engines[i].GetBlock(0)
		if !bytes.Equal(b0.BlockHash, bi.BlockHash) {
			t.Fatalf("engine %d block 0 hash mismatch", i)
		}
	}

	// Cycle 1
	for i, eng := range engines {
		eng.Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{10 + byte(i + 1)},
			Submitter: peers[i].UID.RootID,
		})
	}

	var rootArr2 [32]byte
	var temp2 [32]byte = engines[0].st.Root()
	copy(rootArr2[:], temp2[:])
	triad := SelectTriad(peers, 0, len(peers))
	indices := triadToIndices(peers, triad)
	for _, idx := range indices {
		engines[idx].RunCycle()
	}

	for i, eng := range engines {
		if eng.BlockCount() != 2 {
			t.Fatalf("engine %d: expected 2 blocks, got %d", i, eng.BlockCount())
		}
	}
	for i := 1; i < 3; i++ {
		b0 := engines[0].GetBlock(1)
		bi := engines[i].GetBlock(1)
		if !bytes.Equal(b0.BlockHash, bi.BlockHash) {
			t.Fatalf("engine %d block 1 hash mismatch", i)
		}
	}

	// Verify all hashes anchored
	for _, eng := range engines {
		for i := 0; i < 4; i++ {
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

func TestMultiNodeProposerDeterministic(t *testing.T) {
	peers, nodes := makePeersAndNodes("det-a", "det-b", "det-c")
	bus := NewMemoryBus()

	engines := make([]*Engine, 3)
	for i := 0; i < 3; i++ {
		engines[i] = NewEngineWithPeers(nodes[i], time.Hour, bus, peers)
		engines[i].cfg.MinLambda1 = 0.001
	}

	// All engines compute VRF for cycle 0
	var rArr [32]byte
	var t2 [32]byte = engines[0].st.Root()
	copy(rArr[:], t2[:])

	proposer0, proof0, _ := SelectProposer(peers, 0, rArr[:], vrfProofsForPeers(peers, 0, rArr[:]))
	for i := 1; i < 3; i++ {
		var rArr [32]byte
		var t2 [32]byte = engines[i].st.Root()
		copy(rArr[:], t2[:])
		p, pr, _ := SelectProposer(peers, 0, rArr[:], vrfProofsForPeers(peers, 0, rArr[:]))
		if p.UID.RootID != proposer0.UID.RootID {
			t.Fatalf("engine %d selected different proposer", i)
		}
		if !bytes.Equal(pr.Gamma, proof0.Gamma) {
			t.Fatalf("engine %d computed different VRF output", i)
		}
	}

	// Run full cycle
	var rootArr2 [32]byte
	var temp2 [32]byte = engines[0].st.Root()
	copy(rootArr2[:], temp2[:])
	triad := SelectTriad(peers, 0, len(peers))
	indices := triadToIndices(peers, triad)
	for _, idx := range indices {
		engines[idx].RunCycle()
	}

	for i, eng := range engines {
		if eng.BlockCount() != 1 {
			t.Fatalf("engine %d: expected 1 block, got %d", i, eng.BlockCount())
		}
		block := eng.GetBlock(0)
		if block.Proposer != proposer0.UID.RootID {
			t.Fatalf("engine %d: proposer mismatch", i)
		}
	}

	t.Logf("Deterministic proposer: all 3 engines agree on proposer and produce identical block")
}

func TestMultiNodeEdgesAndLambda(t *testing.T) {
	peers, nodes := makePeersAndNodes("lambda-a", "lambda-b", "lambda-c")
	bus := NewMemoryBus()

	engines := make([]*Engine, 3)
	for i := 0; i < 3; i++ {
		engines[i] = NewEngineWithPeers(nodes[i], time.Hour, bus, peers)
		engines[i].cfg.MinLambda1 = 0.001
	}

	// Add all 3 entries
	for i := 0; i < 3; i++ {
		engines[0].Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{byte(i + 1)},
			Submitter: peers[i].UID.RootID,
		})
	}

	// Run cycle
	var rootArr [32]byte
	var t2 [32]byte = engines[0].st.Root()
	copy(rootArr[:], t2[:])
	triad := SelectTriad(peers, 0, len(peers))
	indices := triadToIndices(peers, triad)
	for _, idx := range indices {
		engines[idx].RunCycle()
	}

	for i, eng := range engines {
		if eng.BlockCount() != 1 {
			t.Fatalf("engine %d: expected 1 block, got %d", i, eng.BlockCount())
		}
	}

	t.Logf("Edges and lambda: 3 engines, lambda1=%.6f", engines[0].state.Lambda1)
}