package consensus

import (
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func syncTestNode(t *testing.T, seed string) Node {
	t.Helper()
	var networkID [32]byte
	copy(networkID[:], []byte("gleipnir-test-network"))
	uid, err := identity.NewUIDZero(seed, networkID, true)
	if err != nil {
		t.Fatalf("NewUIDZero: %v", err)
	}
	return Node{UID: *uid, Addr: seed}
}

const cycleTestInterval = time.Hour

func newSyncEngine(t *testing.T, node Node) *Engine {
	t.Helper()
	return NewEngine(node, time.Hour)
}

func newSyncEngineWithBus(t *testing.T, node Node, bus GossipChannel) *Engine {
	t.Helper()
	return NewEngineWithPeers(node, time.Hour, bus, []Peer{{UID: node.UID, Addr: node.Addr, Alive: true}})
}

// The cycle number is part of the VRF input (spec §6.2, `alpha_c = c ||
// StateRoot_at_cycle_start`), so every validator must attempt the same cycle or they
// elect different leaders and no quorum forms.
//
// It used to come from e.state.Cycle, which increments on every attempt including
// aborts and skipped empty cycles, so two nodes that started at different times
// disagreed permanently.
func TestCycleDerivedFromCommittedChain(t *testing.T) {
	e := newSyncEngine(t, syncTestNode(t, "cycle-origin-node-entropy"))

	e.mu.Lock()
	if got := e.nextCycleLocked(); got != 0 {
		t.Fatalf("cycle before any block is %d, want 0", got)
	}
	e.mu.Unlock()

	// An attempt counter that moves without committing anything must not move the
	// cycle: nothing has been decided, so there is nothing for peers to agree about.
	for i := 0; i < 5; i++ {
		e.RunCycle()
	}
	e.mu.Lock()
	afterAttempts := e.nextCycleLocked()
	attempts := e.state.Cycle
	e.mu.Unlock()

	if afterAttempts != 0 {
		t.Fatalf("cycle moved to %d after %d aborted attempts with nothing committed; "+
			"it must stay at the committed chain height", afterAttempts, attempts)
	}
	if attempts == 0 {
		t.Fatal("attempt counter did not advance; the test is not exercising the distinction")
	}
}

// Once a block commits, every node's chain is the same length, so the next cycle is
// the same number everywhere. This is the property that makes alpha common.
func TestCycleAdvancesByChainHeight(t *testing.T) {
	e := newSyncEngine(t, syncTestNode(t, "advance-node-entropy"))

	e.mu.Lock()
	e.blocks = append(e.blocks, chain.Block{Index: 0})
	e.blocks = append(e.blocks, chain.Block{Index: 1})
	got := e.nextCycleLocked()
	e.mu.Unlock()

	if got != 2 {
		t.Fatalf("next cycle = %d after two committed blocks, want 2", got)
	}
}

// e.state.Cycle is what key rotation compares EffectiveCycle and ExpiryCycle against
// (spec §8.2). It must keep counting attempts even though the VRF cycle no longer
// follows it, or the rotation windows silently change meaning.
func TestAttemptCounterStillTracksAttempts(t *testing.T) {
	e := newSyncEngine(t, syncTestNode(t, "attempt-counter-node-entropy"))

	before := e.Cycle()
	e.RunCycle()
	after := e.Cycle()

	if after <= before {
		t.Fatalf("attempt counter did not advance: %d -> %d", before, after)
	}
}

// GossipChannel.Publish puts an entry in the bus pool and broadcasts it, but nothing
// drained that pool into the engine -- Snapshot() had no non-test caller. A submission
// to a node that was not the leader therefore stayed there forever.
func TestGossipedEntriesAreIngested(t *testing.T) {
	node := syncTestNode(t, "ingest-node-entropy")
	bus := NewMemoryBus()
	e := newSyncEngineWithBus(t, node, bus)

	var otherSubmitter [16]byte
	otherSubmitter[0] = 0xAA
	remote := chain.ProvenanceEntry{
		Hash:      [32]byte{1, 2, 3},
		Submitter: otherSubmitter,
		Timestamp: 1234,
		Label:     "from-a-peer",
	}
	// Published by a peer, not by this node: only the bus has it.
	bus.Publish(remote)

	e.mu.Lock()
	e.ingestGossipedEntriesLocked()
	got := len(e.pendingEntries)
	e.mu.Unlock()

	if got != 1 {
		t.Fatalf("pending retained entries = %d after ingesting one peer entry, want 1", got)
	}
	if e.pendingEntries[0].Label != "from-a-peer" {
		t.Fatalf("ingested the wrong entry: %+v", e.pendingEntries[0])
	}
}

// Ingestion is idempotent: the pool contains this node's own entries too, and an
// entry retained across a previous abort is already present. Neither may be duplicated,
// because a duplicate would be inserted twice into the Merkle tree and the recomputed
// state root would not match the block the leader proposed.
func TestGossipIngestionDeduplicates(t *testing.T) {
	node := syncTestNode(t, "dedup-node-entropy")
	bus := NewMemoryBus()
	e := newSyncEngineWithBus(t, node, bus)

	entry := chain.ProvenanceEntry{Hash: [32]byte{9}, Label: "dup"}
	bus.Publish(entry)

	e.mu.Lock()
	for i := 0; i < 5; i++ {
		e.ingestGossipedEntriesLocked()
	}
	count := 0
	for _, pending := range e.pendingEntries {
		if pending.Hash == entry.Hash {
			count++
		}
	}
	// Also present in the local pending set, which ingestion must not duplicate.
	e.pending = append(e.pending, entry)
	e.ingestGossipedEntriesLocked()
	e.mu.Unlock()

	if count != 1 {
		t.Fatalf("entry appears %d times in pendingEntries after repeated ingestion, want 1", count)
	}
}

func TestIngestIsNoopWithoutGossip(t *testing.T) {
	e := newSyncEngine(t, syncTestNode(t, "no-gossip-node-entropy"))
	e.mu.Lock()
	e.ingestGossipedEntriesLocked()
	got := len(e.pendingEntries)
	e.mu.Unlock()
	if got != 0 {
		t.Fatalf("ingestion added %d entries with no gossip bus, want 0", got)
	}
}
