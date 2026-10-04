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

// seedVRFProofs publishes every peer's VRF proof for cycle 0 to the bus before any
// engine runs the cycle.
//
// Proposer selection requires a proof from every peer (see SelectProposerVRF), and in
// production those proofs arrive over gossip while the cycle is already in flight.
// Seeding them here removes that timing race from the test so the assertions below
// measure consensus behaviour rather than goroutine scheduling.
func seedVRFProofs(t *testing.T, bus *MemoryBus, peers []Peer, cycle uint64, stateRoot [32]byte) {
	t.Helper()
	alpha := makeAlpha(cycle, stateRoot[:])
	for _, p := range peers {
		proof, err := p.UID.VRFProve(alpha)
		if err != nil {
			t.Fatalf("VRFProve for %s: %v", p.Addr, err)
		}
		bus.PublishVRFProof(VRFProofMsg{
			Cycle:    cycle,
			Proof:    identity.MarshalVRFProof(proof),
			SignerID: p.UID.ID(),
		})
	}
}

// runCyclesConcurrently runs one cycle on every engine at the same time and waits for
// all of them, mirroring production where each node drives its own cycleLoop.
//
// Running the engines one after another cannot produce a block: the first engine to
// run finds no proposal from the elected proposer and the last one to run finds no
// second signature, so quorum is unreachable by construction. Concurrency is part of
// the protocol's operating model, not a test convenience.
func runCyclesConcurrently(engines []*Engine) {
	var wg sync.WaitGroup
	for _, eng := range engines {
		wg.Add(1)
		go func(e *Engine) {
			defer wg.Done()
			e.RunCycle()
		}(eng)
	}
	wg.Wait()
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
	seedVRFProofs(t, bus, peers, 0, rootArr)
	proposer, proof, _ := SelectProposer(peers, 0, rootArr[:], vrfProofsForPeers(peers, 0, rootArr[:]))
	_ = proposer
	_ = proof

	runCyclesConcurrently(engines)

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
			Hash:      [32]byte{10 + byte(i+1)},
			Submitter: peers[i].UID.RootID,
		})
	}

	var rootArr2 [32]byte
	var temp2 [32]byte = engines[0].st.Root()
	copy(rootArr2[:], temp2[:])
	seedVRFProofs(t, bus, peers, 1, rootArr2)
	runCyclesConcurrently(engines)

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

	// Verify all hashes anchored. Each cycle submits one entry per peer, so there are
	// three hashes per cycle, not four.
	for _, eng := range engines {
		for i := 0; i < len(peers); i++ {
			proof, ok := eng.LookupHash([32]byte{byte(i + 1)})
			if !ok || !proof.Found {
				t.Fatalf("missing hash %d", i+1)
			}
			proof, ok = eng.LookupHash([32]byte{10 + byte(i+1)})
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
		engines[i].cfg.SkipEmptyCycles = false
	}

	// The proposer has nothing to build a block from without pending entries, so this
	// test needs them even though its subject is proposer determinism.
	for i := 0; i < 3; i++ {
		engines[i].Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{byte(i + 1)},
			Submitter: peers[i].UID.RootID,
		})
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
	seedVRFProofs(t, bus, peers, 0, rootArr2)
	runCyclesConcurrently(engines)

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
		// Entries are submitted to engine 0 only, so the other engines have nothing in
		// their own pending queue. Without this they would skip the cycle entirely and
		// never contribute a signature, leaving the proposer short of quorum.
		engines[i].cfg.SkipEmptyCycles = false
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
	seedVRFProofs(t, bus, peers, 0, rootArr)
	runCyclesConcurrently(engines)

	for i, eng := range engines {
		if eng.BlockCount() != 1 {
			t.Fatalf("engine %d: expected 1 block, got %d", i, eng.BlockCount())
		}
	}

	t.Logf("Edges and lambda: 3 engines, lambda1=%.6f", engines[0].state.Lambda1)
}
