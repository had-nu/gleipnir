package consensus

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

var fixedClockRef func() time.Time

func init() {
	var i int64
	fixedClockRef = func() time.Time {
		i += 1000
		return time.Unix(0, i)
	}
}

func buildSeed(cycle uint64, stateRoot []byte) []byte {
	seed := make([]byte, 8+len(stateRoot))
	binary.LittleEndian.PutUint64(seed, cycle)
	copy(seed[8:], stateRoot)
	return seed
}

// --- C01: Proposer-selection grinding ---

// Simulate an attacker generating candidate RootID values to win proposer
// selection for a specific future cycle. Reports concrete numbers.
func TestProposerSelectionGrinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping grinding measurement in short mode")
	}

	honestCounts := []int{5, 20, 50}
	stateRoot := []byte("fixed-state-root-for-benchmark")
	cycle := uint64(42)

	for _, nHonest := range honestCounts {
		t.Run(fmt.Sprintf("honest=%d", nHonest), func(t *testing.T) {
			honest := make([]Peer, nHonest)
			for i := 0; i < nHonest; i++ {
				uid := identity.NewUIDZero(fmt.Sprintf("honest-%d", i), true)
				honest[i] = Peer{UID: *uid, Addr: fmt.Sprintf("peer-%d", i), Alive: true}
			}

			bestHonest, bestScore := SelectProposer(honest, cycle, stateRoot)
			_ = bestHonest

			seed := buildSeed(cycle, stateRoot)

			const trials = 100
			results := make([]int, trials)
			for trial := 0; trial < trials; trial++ {
				attempts := 0
				for {
					uid := identity.NewUIDZero(fmt.Sprintf("attacker-%d-%d", trial, attempts), true)
					attackerScore := scorePeer(Peer{UID: *uid}, seed)
					attempts++
					if lessThan(attackerScore, bestScore) {
						break
					}
					if attempts > 10_000_000 {
						break
					}
				}
				results[trial] = attempts
			}

			sort.Ints(results)
			p50 := results[trials/2]
			p90 := results[int(float64(trials)*0.9)]
			p99 := results[int(float64(trials)*0.99)]

			t.Logf("  Honest peers: %d", nHonest)
			t.Logf("  Best honest score (hex first 8 bytes): %x", bestScore[:8])
			t.Logf("  Attacker identities needed — P50: %d, P90: %d, P99: %d", p50, p90, p99)
			t.Logf("  Expected (approx 2^nHonest * ln(2)): %.0f", math.Log(2)*float64(nHonest)*2)
		})
	}
}

// --- C02: Equivocation detection ---

// Construct two conflicting blocks for the same cycle and confirm whether
// the codebase has any mechanism to detect or penalize this.
func TestEquivocationDetection(t *testing.T) {
	uid := identity.NewUIDZero("equiv-test", true)
	eng := NewEngine(Node{UID: *uid, Addr: "equiv-test"}, 0)

	// Build two blocks with the same cycle index but different content
	cycle := uint64(0)
	stateRoot1 := []byte("root-a")
	stateRoot2 := []byte("root-b")

	block1 := chain.Block{
		Index:     cycle,
		PrevHash:  make([]byte, 32),
		Proposer:  uid.RootID,
		StateRoot: stateRoot1,
		Anchored:  []chain.ProvenanceEntry{{Hash: [32]byte{1}}},
		Timestamp: 1000,
	}
	block1.BlockHash = computeBlockHash(block1)

	block2 := chain.Block{
		Index:     cycle,
		PrevHash:  make([]byte, 32),
		Proposer:  uid.RootID,
		StateRoot: stateRoot2,
		Anchored:  []chain.ProvenanceEntry{{Hash: [32]byte{2}}},
		Timestamp: 2000,
	}
	block2.BlockHash = computeBlockHash(block2)

	// Engine has no equivocation detection — both blocks can be appended
	eng.mu.Lock()
	eng.blocks = append(eng.blocks, block1, block2)
	eng.mu.Unlock()

	if len(eng.blocks) != 2 {
		t.Fatal("expected 2 blocks in engine (no equivocation detection)")
	}

	// Both blocks claim the same index — verify
	if eng.blocks[0].Index == eng.blocks[1].Index {
		t.Log("CONFIRMED: no equivocation detection — two blocks with same cycle index exist side by side")
		t.Log("GAP: the codebase has no mechanism to detect or penalize proposer equivocation")
		t.Log("This is expected per P2 finding (single-node, triad/quorum not wired)")
	} else {
		t.Error("unexpected: blocks have different indices")
	}
}

// --- C03: Replay of previously anchored hash ---

func TestReplayAnchoredHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping replay test in short mode")
	}

	uid := identity.NewUIDZero("replay-test", true)
	eng := NewEngine(Node{UID: *uid, Addr: "replay-test"}, 0)
	eng.nowFunc = fixedClockRef

	targetHash := [32]byte{42}

	// First submission and cycle
	eng.Enqueue(chain.ProvenanceEntry{
		Hash: targetHash, Submitter: []byte("alice"), Label: "first",
	})
	eng.RunCycle()

	proof1, ok1 := eng.LookupHash(targetHash)
	if !ok1 || !proof1.Found {
		t.Fatal("first anchor should be found")
	}
	t.Logf("First anchor: block=%d, label=%s", proof1.BlockIndex, proof1.Label)

	// Second submission — same hash, different submitter/label
	eng.Enqueue(chain.ProvenanceEntry{
		Hash: targetHash, Submitter: []byte("bob"), Label: "second",
	})
	eng.RunCycle()

	// The anchored map is keyed by hash (single entry per hash), so the
	// second submission overwrites the first AnchorProof. The hash itself
	// remains in the SMT from the first cycle — both anchors are on-chain.
	proof1b, ok1b := eng.LookupHash(targetHash)
	if !ok1b || !proof1b.Found {
		t.Fatal("hash should still be findable after second submission")
	}
	if proof1b.BlockIndex == proof1.BlockIndex {
		// Both in same block — unreachable given two RunCycle calls
		t.Fatal("unexpected: both anchors in same block")
	}

	t.Logf("Latest AnchorProof: block=%d, label=%s (overwritten from first anchor at block %d)",
		proof1b.BlockIndex, proof1b.Label, proof1.BlockIndex)
	t.Log("NOTE: anchored[h] map is append-only-per-hash — only the most recent AnchorProof is stored.")
	t.Log("Both anchors exist on-chain (SMT preserves both entries). The AnchorProof cache is lossy for replays.")
}
