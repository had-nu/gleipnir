// PREPARE phase logic for two-phase BFT consensus.
package consensus

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/state"
)

// PrepareResult contains the result of the PREPARE phase.
type PrepareResult struct {
	Block         *chain.Block      // Candidate block B
	PrepareSigs   map[string][]byte // SignerID -> signature
	PrepareBitmap []byte            // Bitmap of signers
	LeaderID      string            // Leader's UID hex
	QuorumReached bool              // Whether Q signatures collected
	Err           error             // Error if any
}

// RunPreparePhase executes the PREPARE phase of consensus.
// The leader proposes a candidate block, validators verify and sign.
// Returns PrepareResult with collected PREPARE signatures.
// If checkQuorum is false, skips the final quorum check (useful for multi-step test scenarios).
// requiredQuorum is the number of signatures needed (Q=1 in degraded mode, ceil(2N/3) otherwise).
func (e *Engine) RunPreparePhase(cycle uint64, rootArr [32]byte, pendingEntries []chain.ProvenanceEntry, checkQuorum bool, requiredQuorum int) *PrepareResult {
	myUIDHex := e.node.UID.ID()

	// Determine proposer peers
	proposerPeers := e.peers
	if e.gossip == nil {
		proposerPeers = []Peer{{UID: e.node.UID, Addr: e.node.Addr, Alive: true}}
	}

	// Compute local VRF proof
	alpha := makeAlpha(cycle, rootArr[:])
	localProof, vrfErr := e.node.UID.VRFProve(alpha)
	if vrfErr != nil {
		return &PrepareResult{Err: fmt.Errorf("VRF proof error: %w", vrfErr)}
	}

	// Publish VRF proof
	if e.gossip != nil {
		proofBytes := identity.MarshalVRFProof(localProof)
		e.gossip.PublishVRFProof(VRFProofMsg{Cycle: cycle, Proof: proofBytes, SignerID: myUIDHex})
	}

	// Collect VRF proofs
	vrfProofs := make(map[string]*identity.VRFProof)
	vrfProofs[myUIDHex] = localProof
	if e.gossip != nil {
		for _, msg := range e.gossip.GetVRFProofs(cycle) {
			p, err := identity.UnmarshalVRFProof(msg.Proof)
			if err == nil {
				if _, exists := vrfProofs[msg.SignerID]; !exists {
					vrfProofs[msg.SignerID] = p
				}
			}
		}
	}

	// Select proposer
	proposer, _, vrfErr := SelectProposer(proposerPeers, cycle, rootArr[:], vrfProofs)
	if vrfErr != nil {
		return &PrepareResult{Err: fmt.Errorf("VRF proposer selection failed: %w", vrfErr)}
	}
	proposerHex := proposer.UID.ID()
	amProposer := proposerHex == myUIDHex

	// Check if proposer is active
	if nodeState, ok := e.state.Nodes[proposerHex]; ok && nodeState.Status <= 0 {
		return &PrepareResult{Err: fmt.Errorf("proposer %s is inactive", proposerHex)}
	}

	// Get previous block hash
	prevHash := make([]byte, 32)
	if len(e.blocks) > 0 {
		prevHash = e.blocks[len(e.blocks)-1].BlockHash
	}

	var entries []chain.ProvenanceEntry
	var block *chain.Block

	if amProposer {
		// PROPOSER: Collect entries - prefer gossip snapshot in multi-node, fall back to pendingEntries
		if e.gossip != nil && !checkQuorum {
			// First proposal: create new block
			entries = e.gossip.Snapshot()
		} else if e.gossip != nil && checkQuorum {
			// Quorum check: retrieve already-proposed block from gossip
			proposal := e.gossip.GetProposed(cycle)
			if proposal == nil {
				return &PrepareResult{Err: fmt.Errorf("no proposal from proposer for quorum check")}
			}
			block = proposal
			entries = block.Anchored
		} else {
			entries = make([]chain.ProvenanceEntry, len(pendingEntries))
			copy(entries, pendingEntries)
		}

		if len(entries) == 0 && block == nil {
			return &PrepareResult{Err: fmt.Errorf("no entries to propose")}
		}

		if block == nil {
			// Deduplicate by hash
			seen := make(map[[32]byte]int)
			unique := make([]chain.ProvenanceEntry, 0, len(entries))
			for _, entry := range entries {
				if _, dup := seen[entry.Hash]; !dup {
					seen[entry.Hash] = 1
					unique = append(unique, entry)
				}
			}
			entries = unique

			// Build candidate block B
			block = &chain.Block{
				Index:           cycle,
				PrevHash:        prevHash,
				Proposer:        proposer.UID.RootID,
				Anchored:        entries,
				Lambda1:         e.state.Lambda1,
				Timestamp:       e.nowFunc().UnixNano(),
				Quorum:          e.quorumConfig,
				Validators:      make([]chain.ValidatorInfo, 0, len(e.peers)),
				PrepareSigs:     make([][]byte, 0, len(e.peers)),
				ProtocolVersion: 2,
				// Reference the key rotation epoch in force for this block (spec §8).
				KeyRotationEpoch: e.keyRotationEpochLocked(),
			}

			// Degraded mode: add label to block metadata (spec §5.5)
			if requiredQuorum == 1 {
				block.Metadata = map[string][]byte{
					"3cp:degraded-block": []byte("true"),
				}
			}

			for _, p := range e.peers {
				block.Validators = append(block.Validators, chain.ValidatorInfo{
					ValidatorID:  p.UID.RootID,
					Dilithium3PK: p.UID.PublicKey,
					VRFPK:        p.UID.VRFPublicKey,
					ContractHash: p.UID.ContractHash,
				})
			}

			// Insert entries into SMT
			for i := range entries {
				var h [32]byte
				copy(h[:], entries[i].Hash[:])
				if err := e.st.Insert(h[:], entries[i].Hash[:]); err != nil {
					log.Printf("IPC cycle %d: SMT Insert: %v", cycle, err)
				}
			}

			stateRootArr := e.st.Root()
			block.StateRoot = stateRootArr[:]

			// Compute block hash
			blockHash := chain.ComputeBlockHash(block)
			block.BlockHash = blockHash

			// Proposer signs the candidate block hash (PREPARE signature)
			proposerSig := identity.SignDilithium(e.node.UID.SecretKey, blockHash)

			// Add signature to block's PrepareSigs before publishing
			block.PrepareSigs = append(block.PrepareSigs, proposerSig)

			// Broadcast proposal and signature
			if e.gossip != nil {
				e.gossip.Propose(*block, myUIDHex)
				e.gossip.PublishSig(BlockSig{Cycle: cycle, Sig: proposerSig, SignerID: myUIDHex})
			}

		}
	} else {
		// NON-PROPOSER: Read proposer's block from gossip, waiting briefly for it to
		// be published rather than racing it (spec §6.1 proposal timeout).
		if e.gossip == nil {
			return &PrepareResult{Err: fmt.Errorf("no gossip in multi-node mode")}
		}
		proposal := e.waitForProposal(e.ctx, cycle, e.proposalWait())
		if proposal == nil {
			return &PrepareResult{Err: fmt.Errorf("no proposal from proposer %s", proposerHex)}
		}
		block = proposal
		entries = block.Anchored

		// Insert entries into SMT (must match proposer's root)
		for i := range entries {
			var h [32]byte
			copy(h[:], entries[i].Hash[:])
			if err := e.st.Insert(h[:], entries[i].Hash[:]); err != nil {
				log.Printf("IPC cycle %d: SMT Insert: %v", cycle, err)
			}
		}

		// Verify SMT root matches proposer's
		localRoot := e.st.Root()
		if string(localRoot[:]) != string(block.StateRoot) {
			return &PrepareResult{Err: fmt.Errorf("SMT root mismatch: local=%x proposal=%x",
				localRoot[:], block.StateRoot)}
		}

		// Verify candidate block hash
		expectedHash := chain.ComputeBlockHash(block)
		if string(expectedHash) != string(block.BlockHash) {
			return &PrepareResult{Err: fmt.Errorf("block hash mismatch")}
		}

		// Verify proposer's signature on block hash (overlap-aware, spec §8)
		if !e.verifySignatureWithOverlap(proposer.UID.RootID, block.BlockHash, block.PrepareSigs[0], cycle) {
			return &PrepareResult{Err: fmt.Errorf("proposer signature verification failed")}
		}

		// Sign the block hash as PREPARE vote
		mySig := identity.SignDilithium(e.node.UID.SecretKey, block.BlockHash)
		e.gossip.PublishSig(BlockSig{Cycle: cycle, Sig: mySig, SignerID: myUIDHex})
	}

	if block == nil {
		return &PrepareResult{Err: fmt.Errorf("internal error: block is nil before signature verification")}
	}

	// collectValidSigs gathers the PREPARE signatures visible on the bus and returns
	// only those that verify under the signer's registered key.
	collectValidSigs := func() map[string][]byte {
		prepareSigs := make(map[string][]byte)

		// Add local signature
		if amProposer {
			prepareSigs[myUIDHex] = block.PrepareSigs[0]
		} else if e.gossip != nil {
			// Local signature was already published above
			for _, s := range e.gossip.GetSigs(cycle) {
				if s.SignerID == myUIDHex {
					prepareSigs[myUIDHex] = s.Sig
					break
				}
			}
		} else {
			// Single-node non-proposer case: signature already added to block
			prepareSigs[myUIDHex] = block.PrepareSigs[0]
		}

		// Collect from gossip
		if e.gossip != nil {
			for _, s := range e.gossip.GetSigs(cycle) {
				if _, exists := prepareSigs[s.SignerID]; !exists {
					prepareSigs[s.SignerID] = s.Sig
				}
			}
		}

		valid := make(map[string][]byte, len(prepareSigs))
		for signerID, sig := range prepareSigs {
			// Find validator identity
			var signerRootID [16]byte
			found := false
			for _, p := range e.peers {
				if p.UID.ID() == signerID {
					signerRootID = p.UID.RootID
					found = true
					break
				}
			}
			if !found {
				continue // Unknown validator
			}

			// Overlap-aware verification (spec §8): a validator mid-rotation signs with
			// either its outgoing or its incoming key, and both must verify.
			if e.verifySignatureWithOverlap(signerRootID, block.BlockHash, sig, cycle) {
				valid[signerID] = sig
			} else {
				log.Printf("IPC cycle %d: invalid PREPARE signature from %s", cycle, signerID)
			}
		}
		return valid
	}

	validPrepareSigs := collectValidSigs()

	var quorumReached bool
	if checkQuorum {
		// The proposer only just published the candidate, so validators are still
		// verifying it. Wait for their signatures instead of deciding immediately,
		// otherwise the quorum check loses the race it is supposed to arbitrate.
		if e.gossip != nil && len(validPrepareSigs) < requiredQuorum {
			if e.waitForSignatures(e.ctx, cycle, requiredQuorum, e.proposalWait(), collectValidSigs) {
				validPrepareSigs = collectValidSigs()
			}
		}
		quorumReached = len(validPrepareSigs) >= requiredQuorum
	}

	// Build bitmap
	bitmap := make([]byte, (len(e.peers)+7)/8)
	for i, p := range e.peers {
		if _, ok := validPrepareSigs[p.UID.ID()]; ok {
			bitmap[i/8] |= 1 << (i % 8)
		}
	}

	// Defensive check
	if block == nil {
		return &PrepareResult{Err: fmt.Errorf("internal error: block is nil in PrepareResult")}
	}

	return &PrepareResult{
		Block:         block,
		PrepareSigs:   validPrepareSigs,
		PrepareBitmap: bitmap,
		LeaderID:      proposerHex,
		QuorumReached: quorumReached,
	}
}

// proposalWait returns how long a validator waits for the elected proposer's block.
//
// It is bounded by a fraction of the cycle budget so the wait can never exceed the
// time available before the next cycle, which keeps a stalled proposer from pushing
// the whole network behind schedule.
func (e *Engine) proposalWait() time.Duration {
	budget := e.cycleTimeout
	if budget <= 0 {
		budget = state.DefaultConfig.CycleTimeout
	}
	if wait := budget / 4; wait > 0 {
		return wait
	}
	return time.Millisecond
}

// waitForProposal polls the gossip bus for the proposer's block for cycle.
//
// Every engine starts its cycle at the same instant, but the elected proposer is only
// one of them and reaches its propose step at a slightly different time. Without a
// wait, validators routinely check for a proposal microseconds before it is published
// and abort, so a cycle only commits when scheduling happens to be favourable. A
// bounded wait is the standard BFT proposal timeout: it costs a little latency in the
// worst case and removes the race otherwise.
//
// The wait is capped and interruptible via ctx, so a missing proposal degrades to
// aborting the cycle rather than hanging.
func (e *Engine) waitForProposal(ctx context.Context, cycle uint64, timeout time.Duration) *chain.Block {
	if timeout <= 0 {
		return e.gossip.GetProposed(cycle)
	}

	const pollInterval = 2 * time.Millisecond
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if block := e.gossip.GetProposed(cycle); block != nil {
			return block
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil
			}
		}
	}
}

// waitForSignatures polls collect until it yields at least quorum valid signatures or
// the timeout elapses, and reports whether quorum was reached.
//
// collect is re-invoked on every tick rather than caching one snapshot, so signatures
// that arrive during the wait are picked up.
func (e *Engine) waitForSignatures(
	ctx context.Context,
	cycle uint64,
	quorum int,
	timeout time.Duration,
	collect func() map[string][]byte,
) bool {
	if timeout <= 0 {
		return len(collect()) >= quorum
	}

	const pollInterval = 2 * time.Millisecond
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if len(collect()) >= quorum {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if time.Now().After(deadline) {
				return len(collect()) >= quorum
			}
		}
	}
}

// quorumRequired computes the required quorum: ceil(2N/3).
func quorumRequired(n int) int {
	return (2*n + 2) / 3
}
