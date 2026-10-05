package consensus

import (
	"testing"

	"github.com/had-nu/gleipnir/pkg/chain"
)

// Regression for the missing SMT rollback.
//
// RunPreparePhase inserts the cycle's entries into e.st so it can compute the block's
// StateRoot, and there was no way to undo that. Every failure path restored only
// pendingEntries, so a cycle that inserted and then failed to reach quorum left this
// node's state root advanced with no block behind it.
//
// The state root is the second component of the VRF input (spec §6.2,
// `alpha_c = c || StateRoot_at_cycle_start`), so from that point this node's alpha
// differed from every peer's permanently: no VRF proof it published could verify, and
// the network deadlocked with no error anywhere. Observed live on a five-node
// topology as "invalid proof from <peer>: VRF verification failed" on every cycle.
//
// The engine is built with a validator set it cannot reach -- no gossip bus, so no
// peer can contribute a signature -- which makes the proposer insert and then fail at
// quorum. Single-node would not exercise this: with Q=1 it self-signs and commits, so
// the root advancing there is correct.
func TestFailedCycleDoesNotAdvanceRoot(t *testing.T) {
	self := syncTestNode(t, "rollback-self-node-entropy")
	other := syncTestNode(t, "rollback-other-node-entropy")

	// No gossip bus: the proposer cannot collect a second signature.
	e := NewEngineWithPeers(self, cycleTestInterval, nil, []Peer{
		{UID: self.UID, Addr: "self", Alive: true},
		{UID: other.UID, Addr: "other", Alive: true},
	})

	var submitter [16]byte
	submitter[0] = 1
	for i := 0; i < 3; i++ {
		if err := e.Enqueue(chain.ProvenanceEntry{
			Hash:      [32]byte{byte(i + 1)},
			Submitter: submitter,
			Label:     "probe",
		}); err != nil {
			t.Fatal(err)
		}
	}

	before := e.GetStateRoot()
	blocksBefore := e.BlockCount()

	e.RunCycle()

	if got := e.BlockCount(); got != blocksBefore {
		t.Fatalf("a block was committed (%d -> %d) despite no quorum being reachable; "+
			"the test is not exercising the rollback path", blocksBefore, got)
	}

	after := e.GetStateRoot()
	if string(before) != string(after) {
		t.Fatalf("state root advanced with no block committed:\n before=%x\n after =%x",
			before, after)
	}
}

// The entries must still be pending afterwards: an aborted cycle retains them
// (spec §6.4), so a rollback must not lose work either.
func TestFailedCycleRetainsEntries(t *testing.T) {
	self := syncTestNode(t, "retain-self-node-entropy")
	other := syncTestNode(t, "retain-other-node-entropy")
	e := NewEngineWithPeers(self, cycleTestInterval, nil, []Peer{
		{UID: self.UID, Addr: "self", Alive: true},
		{UID: other.UID, Addr: "other", Alive: true},
	})

	var submitter [16]byte
	submitter[0] = 2
	want := [32]byte{0xAB}
	if err := e.Enqueue(chain.ProvenanceEntry{Hash: want, Submitter: submitter, Label: "keep"}); err != nil {
		t.Fatal(err)
	}

	e.RunCycle()

	e.mu.Lock()
	retained := 0
	for _, entry := range e.pendingEntries {
		if entry.Hash == want {
			retained++
		}
	}
	e.mu.Unlock()

	if retained != 1 {
		t.Fatalf("entry retained %d times after an aborted cycle, want exactly 1", retained)
	}
}
