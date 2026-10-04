// Degraded mode handling for N < MinValidators.
package consensus

import (
	"fmt"
	"log"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

// DegradedMode handles consensus when N < MinValidators.
// In degraded mode, finality is 1-of-N (any single signature suffices).
// Blocks carry the label "3cp:degraded-block" in Metadata.
type DegradedMode struct {
	MinValidators     uint64 // From mandate (default: 4)
	GraceCycles       uint64 // From mandate (default: 10)
	consecutiveNormal uint64 // Cycles with N >= MinValidators and normal quorum
	inDegraded        bool
}

// NewDegradedMode creates a new degraded mode handler.
func NewDegradedMode(minValidators, graceCycles uint64) *DegradedMode {
	return &DegradedMode{
		MinValidators: minValidators,
		GraceCycles:   graceCycles,
	}
}

// CheckDegradedTransition checks if the network should enter or exit degraded mode.
// Returns the updated mode and whether a transition occurred.
func (d *DegradedMode) CheckDegradedTransition(currentValidators int, quorumReached bool) (transitioned bool, enteredDegraded bool) {
	wasDegraded := d.inDegraded

	if !d.inDegraded {
		// Check if we should enter degraded mode
		if uint64(currentValidators) < d.MinValidators {
			d.inDegraded = true
			d.consecutiveNormal = 0
			log.Printf("IPC: entering degraded mode (validators=%d, min=%d)", currentValidators, d.MinValidators)
			return true, true
		}
	} else {
		// In degraded mode - check if we can exit
		if uint64(currentValidators) >= d.MinValidators && quorumReached {
			d.consecutiveNormal++
			if d.consecutiveNormal >= d.GraceCycles {
				d.inDegraded = false
				d.consecutiveNormal = 0
				log.Printf("IPC: exiting degraded mode after %d consecutive normal cycles", d.GraceCycles)
				return true, false
			}
		} else {
			d.consecutiveNormal = 0
		}
	}

	return d.inDegraded != wasDegraded, d.inDegraded
}

// IsDegraded returns true if currently in degraded mode.
func (d *DegradedMode) IsDegraded() bool {
	return d.inDegraded
}

// ApplyDegradedBlock applies degraded mode rules to a block.
// In degraded mode: 1-of-N finality, label added to Metadata.
func (d *DegradedMode) ApplyDegradedBlock(block *chain.Block, peers []Peer, myUIDHex string) error {
	if !d.inDegraded {
		return nil
	}

	// In degraded mode any single valid signature suffices.
	//
	// PrepareSigs is ordered by set bit in PrepareSigsBitmap, NOT by peer index, so the
	// signer of each signature has to be recovered through the bitmap. Indexing
	// PrepareSigs by peer position verifies signatures against the wrong keys whenever
	// the signing set is not a prefix of the validator set.
	sigIdx := 0
	validSig := []byte(nil)
	validPeerIdx := -1

	for peerIdx := range peers {
		if peerIdx/8 >= len(block.PrepareSigsBitmap) {
			break
		}
		if block.PrepareSigsBitmap[peerIdx/8]&(1<<(peerIdx%8)) == 0 {
			continue
		}
		if sigIdx >= len(block.PrepareSigs) {
			break
		}
		sig := block.PrepareSigs[sigIdx]
		sigIdx++
		if len(sig) == 0 {
			continue
		}
		pubKey := peers[peerIdx].UID.PublicKey[:]
		if identity.VerifyDilithium(pubKey, block.BlockHash, sig) {
			validSig = sig
			validPeerIdx = peerIdx
			break
		}
	}

	if validSig == nil {
		return fmt.Errorf("no valid signature in degraded mode")
	}

	// Keep only the valid signature, and rewrite the bitmap so it still describes the
	// surviving signature. Leaving stale bits set would make verifyPrepareQuorum index
	// past the end of PrepareSigs and reject the block on every other node.
	block.PrepareSigs = [][]byte{validSig}
	bitmap := make([]byte, (len(peers)+7)/8)
	bitmap[validPeerIdx/8] |= 1 << (validPeerIdx % 8)
	block.PrepareSigsBitmap = bitmap

	// Add degraded block label to Metadata
	if block.Metadata == nil {
		block.Metadata = make(map[string][]byte)
	}
	block.Metadata["3cp:degraded-block"] = []byte("true")

	return nil
}

// GetConsensusConfig returns the current consensus configuration for a mandate.
func GetConsensusConfig(mandate *chain.MandateEntry) (minValidators, graceCycles uint64) {
	minValidators = 4
	graceCycles = 10

	for _, rule := range mandate.Rules {
		if rule.EventClass == "3cp:consensus-config" {
			if v, ok := rule.Fields["MinValidators"].(float64); ok {
				minValidators = uint64(v)
			}
			if v, ok := rule.Fields["GraceCycles"].(float64); ok {
				graceCycles = uint64(v)
			}
		}
	}
	return
}

// QuorumRequired computes the required quorum: ceil(2N/3).
func QuorumRequired(n int) int {
	return (2*n + 2) / 3
}
