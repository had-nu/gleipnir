// PREPARE phase logic for two-phase BFT consensus.
package consensus

import (
	"fmt"
	"log"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

// PrepareResult contains the result of the PREPARE phase.
type PrepareResult struct {
	Block           *chain.Block          // Candidate block B
	PrepareSigs     map[string][]byte     // SignerID -> signature
	PrepareBitmap   []byte                // Bitmap of signers
	LeaderID        string                // Leader's UID hex
	QuorumReached   bool                  // Whether Q signatures collected
	Err             error                 // Error if any
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
				Index:      cycle,
				PrevHash:   prevHash,
				Proposer:   proposer.UID.RootID,
				Anchored:   entries,
				Lambda1:    e.state.Lambda1,
				Timestamp:  e.nowFunc().UnixNano(),
				Quorum:     e.quorumConfig,
				Validators: make([]chain.ValidatorInfo, 0, len(e.peers)),
				PrepareSigs: make([][]byte, 0, len(e.peers)),
				ProtocolVersion: 2,
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

		} else {
			// NON-PROPOSER: Read proposer's block from gossip
			if e.gossip == nil {
				return &PrepareResult{Err: fmt.Errorf("no gossip in multi-node mode")}
			}
			proposal := e.gossip.GetProposed(cycle)
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

			// Verify proposer's signature on block hash
			proposerPubKey := proposer.UID.PublicKey[:]
			if !identity.VerifyDilithium(proposerPubKey, block.BlockHash, block.PrepareSigs[0]) {
				return &PrepareResult{Err: fmt.Errorf("proposer signature verification failed")}
			}

			// Sign the block hash as PREPARE vote
			mySig := identity.SignDilithium(e.node.UID.SecretKey, block.BlockHash)
			e.gossip.PublishSig(BlockSig{Cycle: cycle, Sig: mySig, SignerID: myUIDHex})
		}
	}

	// Collect PREPARE signatures from all validators
	prepareSigs := make(map[string][]byte)

	// Add local signature
	if amProposer {
		prepareSigs[myUIDHex] = block.PrepareSigs[0]
	} else if e.gossip != nil {
		// Local signature was already published above
		sigs := e.gossip.GetSigs(cycle)
		for _, s := range sigs {
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
		sigs := e.gossip.GetSigs(cycle)
		for _, s := range sigs {
			if _, exists := prepareSigs[s.SignerID]; !exists {
				prepareSigs[s.SignerID] = s.Sig
			}
		}
	}

	// Verify each PREPARE signature against validator set
	if block == nil {
		return &PrepareResult{Err: fmt.Errorf("internal error: block is nil before signature verification")}
	}
	validPrepareSigs := make(map[string][]byte)
	for signerID, sig := range prepareSigs {
		// Find validator public key
		var pubKey [1952]byte
		for _, p := range e.peers {
			if p.UID.ID() == signerID {
				pubKey = p.UID.PublicKey
				break
			}
		}
		if pubKey == [1952]byte{} {
			continue // Unknown validator
		}

		if identity.VerifyDilithium(pubKey[:], block.BlockHash, sig) {
			validPrepareSigs[signerID] = sig
		} else {
			log.Printf("IPC cycle %d: invalid PREPARE signature from %s", cycle, signerID)
		}
	}

	var quorumReached bool
	if checkQuorum {
		// Check quorum using requiredQuorum (Q=1 in degraded mode, ceil(2N/3) otherwise)
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

// quorumRequired computes the required quorum: ceil(2N/3).
func quorumRequired(n int) int {
	return (2*n + 2) / 3
}