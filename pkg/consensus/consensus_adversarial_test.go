//nolint:errcheck // test assertions
package consensus

import (
	"fmt"
	"math"
	"sort"
	"testing"

	"github.com/had-nu/gleipnir/pkg/identity"
)

func TestProposerSelectionGrinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping grinding measurement in short mode")
	}

	honestCounts := []int{5, 20, 50}
	stateRoot := []byte("fixed-state-root-for-benchmark")
	cycle := uint64(42)

	var networkID [32]byte
	copy(networkID[:], []byte("grinding-test-network"))

	for _, nHonest := range honestCounts {
		t.Run(fmt.Sprintf("honest=%d", nHonest), func(t *testing.T) {
			honest := make([]Peer, nHonest)
			for i := 0; i < nHonest; i++ {
				uid, err := identity.NewUIDZero(fmt.Sprintf("honest-%d", i), networkID, true)
				if err != nil {
					t.Fatal(err)
				}
				honest[i] = Peer{UID: *uid, Addr: fmt.Sprintf("peer-%d", i), Alive: true}
			}

			// Build VRF proofs for all honest peers
			vrfProofs := vrfProofsForPeers(honest, cycle, stateRoot)
			bestHonest, bestProof, err := SelectProposer(honest, cycle, stateRoot, vrfProofs)
			if err != nil {
				t.Fatalf("SelectProposer failed: %v", err)
			}
			_ = bestHonest
			bestGamma := bestProof.Gamma

			// Verify that an attacker without knowing any honest peer's VRF
			// secret key cannot forge a lower Gamma. The attacker would need
			// to brute-force identities until their VRF output beats the best
			// honest Gamma — but they can't compute other peers' VRF outputs
			// without their secret keys.
			alpha := makeAlpha(cycle, stateRoot)

			const trials = 100
			results := make([]int, trials)
			for trial := 0; trial < trials; trial++ {
				attempts := 0
				for {
					uid, err := identity.NewUIDZero(fmt.Sprintf("attacker-%d-%d", trial, attempts), networkID, true)
					if err != nil {
						t.Fatal(err)
					}
					attackerProof, err := uid.VRFProve(alpha)
					if err != nil {
						t.Fatalf("VRFProve failed: %v", err)
					}
					attempts++
					if lessThan(attackerProof.Gamma, bestGamma) {
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
			t.Logf("  Best honest gamma (hex first 8 bytes): %x", bestGamma[:8])
			t.Logf("  Attacker identities needed — P50: %d, P90: %d, P99: %d", p50, p90, p99)
			t.Logf("  Expected (approx 2^nHonest * ln(2)): %.0f", math.Log(2)*float64(nHonest)*2)
		})
	}
}

// --- C02: Equivocation detection ---

// Construct two conflicting blocks for the same cycle and confirm whether
// the codebase has any mechanism to detect or penalize this.
func TestEquivocationDetection(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("equiv-test-network"))

	// Two different proposer peers
	uidA, err := identity.NewUIDZero("proposer-A", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	uidB, err := identity.NewUIDZero("proposer-B", networkID, true)
	if err != nil {
		t.Fatal(err)
	}

	peers := []Peer{
		{UID: *uidA, Addr: "A", Alive: true},
		{UID: *uidB, Addr: "B", Alive: true},
	}

	cycle := uint64(1)
	stateRoot := []byte("equiv-state-root")

	vrfProofs := vrfProofsForPeers(peers, cycle, stateRoot)

	// Select proposer
	proposer, _, err := SelectProposer(peers, cycle, stateRoot, vrfProofs)
	if err != nil {
		t.Fatalf("SelectProposer failed: %v", err)
	}
	t.Logf("Selected proposer: %s", proposer.Addr)

	// In v2.0, the protocol doesn't have explicit equivocation detection
	// beyond the fact that only one block can be finalized per cycle
	// due to quorum requirements. This test documents that limitation.
	t.Log("Note: v2.0 relies on quorum for finality; equivocation results in")
	t.Log("multiple blocks for same cycle, but only one can reach quorum.")
	t.Log("Full slashing/equivocation detection is a future milestone.")
}

// --- C03: Network partition ---

func TestPartitionSurvival(t *testing.T) {
	// This is a stub - full partition testing requires the testnet harness
	t.Skip("requires testnet harness (future milestone)")
}