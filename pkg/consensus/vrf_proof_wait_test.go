package consensus

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

// delayedBus is a GossipChannel whose proofs arrive after a delay rather than
// immediately, standing in for the real libp2p hop between two containers.
//
// The MemoryBus used elsewhere delivers a Publish to every other engine inside the
// same goroutine, so a test built on it can never observe a node reading its own
// proof set before a peer's has crossed the network. Production crosses a socket,
// and that gap is the whole subject of this test.
type delayedBus struct {
	inner *MemoryBus
	delay time.Duration

	mu      sync.Mutex
	pending []VRFProofMsg
	timers  []*time.Timer
}

func newDelayedBus(inner *MemoryBus, delay time.Duration) *delayedBus {
	return &delayedBus{inner: inner, delay: delay}
}

func (b *delayedBus) Publish(entry chain.ProvenanceEntry) { b.inner.Publish(entry) }
func (b *delayedBus) Snapshot() []chain.ProvenanceEntry   { return b.inner.Snapshot() }

func (b *delayedBus) RemoveEntries(remove map[[32]byte]bool) { b.inner.RemoveEntries(remove) }
func (b *delayedBus) Propose(block chain.Block, proposerID string) {
	b.inner.Propose(block, proposerID)
}
func (b *delayedBus) GetProposed(cycle uint64) *chain.Block { return b.inner.GetProposed(cycle) }
func (b *delayedBus) PublishFinal(block chain.Block, proposerID string) {
	b.inner.PublishFinal(block, proposerID)
}
func (b *delayedBus) GetFinal(cycle uint64) *chain.Block { return b.inner.GetFinal(cycle) }
func (b *delayedBus) PublishSig(sig BlockSig)            { b.inner.PublishSig(sig) }
func (b *delayedBus) GetSigs(cycle uint64) []BlockSig    { return b.inner.GetSigs(cycle) }

// PublishVRFProof defers the proof by b.delay instead of delivering it inline.
func (b *delayedBus) PublishVRFProof(proof VRFProofMsg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.delay <= 0 {
		b.inner.PublishVRFProof(proof)
		return
	}
	b.pending = append(b.pending, proof)
}

func (b *delayedBus) GetVRFProofs(cycle uint64) []VRFProofMsg {
	b.mu.Lock()
	due := b.pending[:0:0]
	for _, p := range b.pending {
		if p.Cycle == cycle {
			due = append(due, p)
		}
	}
	b.pending = removeCycle(b.pending, cycle)
	b.mu.Unlock()

	// Deliver once the delay has elapsed, which is what the transport does.
	if len(due) > 0 {
		t := time.AfterFunc(b.delay, func() {
			for _, p := range due {
				b.inner.PublishVRFProof(p)
			}
		})
		b.mu.Lock()
		b.timers = append(b.timers, t)
		b.mu.Unlock()
	}
	return b.inner.GetVRFProofs(cycle)
}

func removeCycle(in []VRFProofMsg, cycle uint64) []VRFProofMsg {
	out := in[:0]
	for _, p := range in {
		if p.Cycle != cycle {
			out = append(out, p)
		}
	}
	return out
}

// A validator that reads its VRF proof set in the same instant it publishes its own
// proof will miss every peer's proof, because the peer's has not crossed the network
// yet.
//
// SelectProposerVRF requires a proof from EVERY peer and deliberately aborts when one
// is absent, trading liveness for the guarantee that two validators holding different
// subsets cannot elect different proposers. That trade is only sound if the node waits
// long enough for the proofs to arrive first: there is already waitForProposal for
// blocks and waitForSignatures for prepare signatures, but no equivalent for VRF
// proofs, so RunPreparePhase read the set immediately and aborted on a race it could
// not win.
//
// Observed on the five-validator topology: every node published its proof and
// immediately read a set containing only its own, so every cycle aborted with
// "incomplete proof set: no proof from <peer>" and no block ever finalised.
func TestPrepareWaitsForPeersVRFProofs(t *testing.T) {
	peers, nodes := makePeersAndNodes(
		"vrf-wait-validator-1-entropy",
		"vrf-wait-validator-2-entropy",
		"vrf-wait-validator-3-entropy",
	)

	// Long enough to be unambiguous, short enough not to slow the suite.
	const proofDelay = 50 * time.Millisecond

	mem := NewMemoryBus()
	bus := newDelayedBus(mem, proofDelay)

	engines := make([]*Engine, len(nodes))
	for i, n := range nodes {
		engines[i] = NewEngineWithPeers(n, time.Hour, bus, peers)
	}

	// A shared bus cannot carry the per-engine gossip a real network would, so drive
	// the prepare phase directly against one engine and assert only that the proofs
	// it needs are waited for. The alpha is fixed, so the same proofs are valid for
	// whichever node is the proposer.
	cycle := uint64(0)
	var rootArr [32]byte
	alpha := makeAlpha(cycle, rootArr[:])

	// Publish every peer's proof, delayed, exactly as the transport would.
	for _, p := range peers {
		proof, err := p.UID.VRFProve(alpha)
		if err != nil {
			t.Fatalf("VRFProve: %v", err)
		}
		bus.PublishVRFProof(VRFProofMsg{
			Cycle:    cycle,
			Proof:    identity.MarshalVRFProof(proof),
			SignerID: p.UID.ID(),
		})
	}

	e := engines[0]

	// engines[0] is whichever node the VRF selects. It proposes from the gossip pool
	// rather than from its own pending set, so the pool needs an entry or the phase
	// aborts on "no entries to propose" before reaching the assertion under test.
	var submitter [16]byte
	copy(submitter[:], "vrf-wait-submitter")

	mem.Publish(chain.ProvenanceEntry{
		Hash:      [32]byte{0xAA},
		Submitter: submitter,
		Label:     "vrf-wait",
	})

	result := e.RunPreparePhase(cycle, rootArr, nil, false, quorumRequired(len(peers)))

	if result.Err != nil {
		t.Fatalf("RunPreparePhase with delayed proofs: %v\n"+
			"expected the validator to wait for peer proofs to arrive rather than "+
			"reading its own proof set immediately", result.Err)
	}
	if result.LeaderID == "" {
		t.Fatal("RunPreparePhase returned no leader with every proof available")
	}
}

// The wait must stay bounded: a peer that never publishes must degrade to an aborted
// cycle, never to a hung one. An unbounded wait would be strictly worse than the race
// it replaces, since it would stop the node serving gRPC entirely.
func TestPrepareVRFProofWaitIsBounded(t *testing.T) {
	peers, nodes := makePeersAndNodes(
		"vrf-bounded-validator-1-entropy",
		"vrf-bounded-validator-2-entropy",
		"vrf-bounded-validator-3-entropy",
	)

	mem := NewMemoryBus()
	bus := newDelayedBus(mem, time.Hour) // nothing ever arrives
	e := NewEngineWithPeers(nodes[0], time.Hour, bus, peers)
	e.cycleTimeout = 200 * time.Millisecond

	var rootArr [32]byte
	cycle := uint64(0)

	done := make(chan *PrepareResult, 1)
	go func() {
		e.mu.Lock()
		pending := e.pending
		e.mu.Unlock()
		done <- e.RunPreparePhase(cycle, rootArr, pending, false, quorumRequired(len(peers)))
	}()

	select {
	case res := <-done:
		if res.Err == nil {
			t.Fatal("RunPreparePhase succeeded with no peer proofs available; " +
				"a validator must not elect a proposer on its own proof alone")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunPreparePhase blocked for 5s waiting for proofs that never arrive; " +
			"the wait must be bounded by the cycle budget")
	}
}

// Cancelling the engine context must release a validator waiting for proofs, so that
// shutdown does not depend on the timeout expiring.
func TestPrepareVRFProofWaitHonoursContextCancel(t *testing.T) {
	peers, nodes := makePeersAndNodes(
		"vrf-cancel-validator-1-entropy",
		"vrf-cancel-validator-2-entropy",
		"vrf-cancel-validator-3-entropy",
	)

	mem := NewMemoryBus()
	bus := newDelayedBus(mem, time.Hour)
	e := NewEngineWithPeers(nodes[0], time.Hour, bus, peers)
	e.cycleTimeout = time.Hour // far longer than the test will wait

	ctx, cancel := context.WithCancel(e.ctx)
	e.ctx = ctx

	done := make(chan *PrepareResult, 1)
	go func() {
		var rootArr [32]byte
		e.mu.Lock()
		pending := e.pending
		e.mu.Unlock()
		done <- e.RunPreparePhase(0, rootArr, pending, false, quorumRequired(len(peers)))
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunPreparePhase did not return after its context was cancelled")
	}
}
