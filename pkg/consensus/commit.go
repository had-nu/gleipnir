// COMMIT phase logic for two-phase BFT consensus.
package consensus

import (
	"fmt"
	"log"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

// CommitResult contains the result of the COMMIT phase.
type CommitResult struct {
	Block        *chain.Block // Final block B_final
	Committed    bool         // Whether block was committed
	Err          error        // Error if any
}

// RunCommitPhase executes the COMMIT phase of consensus.
// The leader constructs B_final with bitmap+payload+commit sig.
// Validators verify PREPARE quorum before accepting.
func (e *Engine) RunCommitPhase(cycle uint64, prepareResult *PrepareResult) *CommitResult {
	if !prepareResult.QuorumReached {
		return &CommitResult{Err: fmt.Errorf("PREPARE quorum not reached")}
	}

	block := prepareResult.Block
	leaderID := prepareResult.LeaderID
	myUIDHex := e.node.UID.ID()
	amLeader := leaderID == myUIDHex

	// Leader constructs B_final
	if amLeader {
		// Build PrepareSigsPayload: concatenate signatures in bitmap order
		payload := make([]byte, 0)
		for i, p := range e.peers {
			if prepareResult.PrepareBitmap[i/8]&(1<<(i%8)) != 0 {
				if sig, ok := prepareResult.PrepareSigs[p.UID.ID()]; ok {
					payload = append(payload, sig...)
				}
			}
		}

		// Create final block with v2.0 fields
		finalBlock := *block // Copy candidate block
		finalBlock.PrepareSigsBitmap = prepareResult.PrepareBitmap
		
		// Convert PrepareSigs map to slice in bitmap order
		prepareSigsSlice := make([][]byte, 0)
		for i, p := range e.peers {
			if prepareResult.PrepareBitmap[i/8]&(1<<(i%8)) != 0 {
				if sig, ok := prepareResult.PrepareSigs[p.UID.ID()]; ok {
					prepareSigsSlice = append(prepareSigsSlice, sig)
				}
			}
		}
		finalBlock.PrepareSigs = prepareSigsSlice
		finalBlock.ProtocolVersion = 2

		// Leader signs the final block hash (COMMIT signature)
		finalHash := computeBlockHash(finalBlock)
		commitSig := identity.SignDilithium(e.node.UID.SecretKey, finalHash)
		finalBlock.CommitSig = commitSig
		finalBlock.BlockHash = finalHash

		// Broadcast B_final
		if e.gossip != nil {
			e.gossip.Propose(finalBlock, myUIDHex)
		}

		return &CommitResult{
			Block:     &finalBlock,
			Committed: true,
		}
	}

	// NON-LEADER: Verify B_final from leader
	if e.gossip == nil {
		return &CommitResult{Err: fmt.Errorf("no gossip in multi-node mode")}
	}

	finalProposal := e.gossip.GetProposed(cycle)
	if finalProposal == nil {
		return &CommitResult{Err: fmt.Errorf("no B_final from leader")}
	}

	// Verify PREPARE quorum in B_final
	if !verifyPrepareQuorum(finalProposal, e.peers) {
		return &CommitResult{Err: fmt.Errorf("B_final PREPARE quorum verification failed")}
	}

	// Verify leader's COMMIT signature
	leaderPubKey := findValidatorPubKey(e.peers, leaderID)
	if leaderPubKey == [1952]byte{} {
		return &CommitResult{Err: fmt.Errorf("leader %s not in validator set", leaderID)}
	}

	if !identity.VerifyDilithium(leaderPubKey[:], finalProposal.BlockHash, finalProposal.CommitSig) {
		return &CommitResult{Err: fmt.Errorf("leader COMMIT signature verification failed")}
	}

	// Verify block hash matches
	expectedHash := computeBlockHash(*finalProposal)
	if string(expectedHash) != string(finalProposal.BlockHash) {
		return &CommitResult{Err: fmt.Errorf("B_final block hash mismatch")}
	}

	log.Printf("IPC cycle %d: B_final verified, committing", cycle)
	return &CommitResult{
		Block:     finalProposal,
		Committed: true,
	}
}

// verifyPrepareQuorum verifies the PREPARE quorum in a final block.
func verifyPrepareQuorum(block *chain.Block, peers []Peer) bool {
	if block.PrepareSigsBitmap == nil || block.PrepareSigs == nil {
		return false
	}

	requiredQuorum := quorumRequired(len(peers))
	verifiedCount := 0

	for i, p := range peers {
		// Check if this validator is in the bitmap
		if i >= len(block.PrepareSigsBitmap)*8 {
			continue
		}
		if block.PrepareSigsBitmap[i/8]&(1<<(i%8)) == 0 {
			continue
		}

		// Get the corresponding signature from PrepareSigs
		// Signatures are in the same order as set bits in bitmap
		sigIndex := countBitsBefore(block.PrepareSigsBitmap, i)
		if sigIndex >= len(block.PrepareSigs) {
			return false
		}
		sig := block.PrepareSigs[sigIndex]

		// Verify against validator's public key
		if !identity.VerifyDilithium(p.UID.PublicKey[:], block.BlockHash, sig) {
			return false
		}
		verifiedCount++
	}

	return verifiedCount >= requiredQuorum
}

// countBitsBefore counts set bits in bitmap before position pos.
func countBitsBefore(bitmap []byte, pos int) int {
	count := 0
	for i := 0; i < pos; i++ {
		if bitmap[i/8]&(1<<(i%8)) != 0 {
			count++
		}
	}
	return count
}

// findValidatorPubKey finds a validator's public key by UID hex.
func findValidatorPubKey(peers []Peer, uidHex string) [1952]byte {
	for _, p := range peers {
		if p.UID.ID() == uidHex {
			return p.UID.PublicKey
		}
	}
	return [1952]byte{}
}