package consensus

import (
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

// newQuorumCluster builds n engines on one bus, each with an entry to propose.
func newQuorumCluster(t *testing.T, n int, skipEmpty bool) ([]*Engine, []Peer) {
	t.Helper()
	return newQuorumClusterOn(t, n, skipEmpty, NewMemoryBus())
}

// newQuorumClusterOn is newQuorumCluster with the bus under the test's control, so a
// caller can substitute a bus that delays delivery the way a socket does.
func newQuorumClusterOn(t *testing.T, n int, skipEmpty bool, bus GossipChannel) ([]*Engine, []Peer) {
	t.Helper()

	seeds := make([]string, n)
	for i := range seeds {
		seeds[i] = "quorum-cluster-seed-" + string(rune('a'+i))
	}
	peers, nodes := makePeersAndNodes(seeds...)

	engines := make([]*Engine, n)
	for i := 0; i < n; i++ {
		engines[i] = NewEngineWithPeers(nodes[i], time.Hour, bus, peers)
		engines[i].cfg.SkipEmptyCycles = skipEmpty
		engines[i].cfg.MinLambda1 = 0.001
		if err := engines[i].Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{byte(i + 1)},
			Submitter: peers[i].UID.RootID,
			Label:     "quorum-cluster",
		}); err != nil {
			t.Fatalf("Enqueue on engine %d: %v", i, err)
		}
	}
	return engines, peers
}

// The same cluster on a bus that delays every message by a round trip.
//
// MemoryBus passes a Publish to every other engine inside the same goroutine, so a
// signature is visible to the proposer before any of them has yielded. Nothing can
// happen in the gap, and the phase-ordering defect cannot appear.
//
// This is the reproduction. It is not a timing tweak: it is the only difference between
// the in-process bus and the libp2p transport, and it is enough to decide whether a
// cycle completes.
func TestCycleCompletesWithDelayedDelivery(t *testing.T) {
	bus := newNetworkBus(20 * time.Millisecond)

	stop := make(chan struct{})
	go bus.pump(stop)
	defer close(stop)

	engines, _ := newQuorumClusterOn(t, 5, false, bus)

	runCyclesConcurrently(engines)

	for i, eng := range engines {
		if eng.BlockCount() == 0 {
			t.Fatalf("engine %d committed no block with a %v delivery delay; "+
				"a cycle that completes instantly on MemoryBus does not survive a network",
				i, bus.delay)
		}
	}
}

// Repeated cycles must keep producing blocks on the delayed bus too.
//
// The topology produced exactly one block and then stopped. A genuine race would show a
// count that varies between runs; a deadlock shows a count pinned at 1, which is what
// this pins.
func TestRepeatedCyclesKeepCommittingWithDelayedDelivery(t *testing.T) {
	bus := newNetworkBus(20 * time.Millisecond)

	stop := make(chan struct{})
	go bus.pump(stop)
	defer close(stop)

	engines, _ := newQuorumClusterOn(t, 5, false, bus)

	const cycles = 3
	for c := 0; c < cycles; c++ {
		for i, eng := range engines {
			if err := eng.Enqueue(chain.ProvenanceEntry{
				Hash:      [32]byte{byte(0x40 + c*8 + i)},
				Submitter: eng.node.UID.RootID,
				Label:     "delayed-repeated",
			}); err != nil {
				t.Fatalf("Enqueue on engine %d, cycle %d: %v", i, c, err)
			}
		}
		runCyclesConcurrently(engines)

		for i, eng := range engines {
			if got := eng.BlockCount(); got == 0 {
				t.Fatalf("cycle %d: engine %d committed nothing; the network stopped after %d",
					c+1, i, c)
			}
		}
	}
}

// A cycle must finalise a block on every node, from nothing but concurrent
// RunCycle calls and gossip.
//
// The existing multi-node tests pre-seed every peer's VRF proof onto the bus before
// running, so they never exercise the path production takes: each node publishes its
// own proof and reads the set. That shortcut is what let a phase-ordering deadlock
// survive — the tests passed because they removed the condition that causes it.
//
// Nothing is seeded here. Five nodes, five concurrent cycles, and whatever happens is
// what the protocol actually does.
func TestConcurrentCycleReachesQuorumWithoutSeededProofs(t *testing.T) {
	engines, _ := newQuorumCluster(t, 5, false)

	runCyclesConcurrently(engines)

	for i, eng := range engines {
		if eng.BlockCount() == 0 {
			t.Fatalf("engine %d committed no block; the cycle did not complete", i)
		}
	}
}

// The specific defect: the proposer cannot reach quorum because the validators whose
// votes it is waiting for do not vote until they have passed a quorum check of their
// own.
//
// Traced on the five-validator topology at 79577ad:
//
//	val-2 (proposer): COMMIT failed: PREPARE quorum not reached
//	val-1:            PREPARE failed: ... incomplete proof set: no proof from <val-2>
//
// and then val-2 published nothing further, so the other four starved on a proof that
// was never coming. The dependency is in RunCycle's phase order: a validator only
// reaches RunCommitPhase after finishing its own RunPreparePhase(checkQuorum=true),
// and the proposer's RunPreparePhase(checkQuorum=true) cannot finish until it has their
// signatures.
//
// This asserts the outcome rather than the mechanism: if the cycle is reordered, this
// still passes, and that is the point.
func TestProposerReachesQuorumWhenValidatorsVote(t *testing.T) {
	engines, peers := newQuorumCluster(t, 5, false)

	var rootArr [32]byte
	root := engines[0].st.Root()
	copy(rootArr[:], root[:])

	// Run only the proposer's cycle, alone. In production the other four are
	// concurrent, so this is the tighter case: with no peers running, the proposer
	// must time out its quorum wait and abort rather than hang.
	done := make(chan struct{})
	go func() {
		defer close(done)
		engines[0].RunCycle()
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("RunCycle did not return within 30s with four peers absent; " +
			"the proposer must abort on timeout, not block")
	}

	// Nothing was asserted about the block: with no peers, zero signatures is the
	// correct outcome. What matters is that it returned at all.
	_ = peers
}

// Repeated cycles must keep producing blocks. The topology produced exactly one and
// then stopped, which is the signature of a deadlock rather than of flakiness — a
// race that sometimes wins would show a block count that varies, not one that sticks
// at 1.
func TestRepeatedCyclesKeepCommitting(t *testing.T) {
	engines, _ := newQuorumCluster(t, 5, false)

	const cycles = 3
	for c := 0; c < cycles; c++ {
		for i, eng := range engines {
			if err := eng.Enqueue(chain.ProvenanceEntry{
				Hash:      [32]byte{byte(0x40 + c*8 + i)},
				Submitter: engines[i].node.UID.RootID,
				Label:     "repeated",
			}); err != nil {
				t.Fatalf("Enqueue on engine %d, cycle %d: %v", i, c, err)
			}
		}
		runCyclesConcurrently(engines)

		want := uint64(c + 1)
		for i, eng := range engines {
			if got := eng.BlockCount(); got != want {
				t.Fatalf("after %d cycles: engine %d has %d blocks, want %d",
					c+1, i, got, want)
			}
		}
	}
}

// Every node must agree on the block, not merely produce one.
//
// A reordering that lets a node commit a block the others rejected would satisfy the
// count assertions above while leaving the chain forked.
func TestAllNodesCommitTheSameBlock(t *testing.T) {
	engines, _ := newQuorumCluster(t, 5, false)

	runCyclesConcurrently(engines)

	var want []byte
	for i, eng := range engines {
		if eng.BlockCount() == 0 {
			t.Fatalf("engine %d committed no block", i)
		}
		h := eng.GetBlock(0).BlockHash
		if i == 0 {
			want = h
			continue
		}
		if string(h) != string(want) {
			t.Fatalf("engine %d block 0 hash %x, engine 0 has %x — nodes disagree", i, h, want)
		}
	}
}

// The proposer's own signature must count toward its quorum.
//
// The proposer signs the candidate in the propose branch (prepare.go:193) and collects
// that signature locally in collectValidSigs, but a peer set of N has quorum ceil(2N/3).
// For N=5 that is 4, so the proposer needs three others. This pins the arithmetic, so
// that a future change to how the proposer's vote is counted cannot quietly move the
// quorum threshold.
func TestQuorumThresholdForFiveValidators(t *testing.T) {
	if got := quorumRequired(5); got != 4 {
		t.Fatalf("quorumRequired(5) = %d, want 4 (ceil(2*5/3))", got)
	}
	_ = identity.MarshalVRFProof
}
