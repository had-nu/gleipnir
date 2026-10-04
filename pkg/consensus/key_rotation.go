// Key rotation integration — 3CP v2.0 spec §8.
//
// The consensus engine owns three responsibilities:
//
//   - admit rotations: a rotation is validated against the five rules of §8.2 and
//     enqueued as a provenance entry labelled "3cp:key-rotation:v1";
//   - accept rotations: when a rotation lands in a block, it is validated and folded
//     into the validator's key history;
//   - honour rotations: PREPARE and COMMIT signatures are verified against whichever
//     keys are authoritative for the signing validator in that cycle, so a rotation
//     never requires the whole network to upgrade in lockstep.
package consensus

import (
	"context"
	"log"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/state"
	"github.com/had-nu/gleipnir/pkg/validation"
)

// initKeyRotationLocked wires the key rotation validator. Called once during
// construction, before the engine is shared across goroutines.
func (e *Engine) initKeyRotationLocked() {
	e.keyRotationValidator = validation.NewKeyRotationValidator(
		e.state.ValidatorSet, e.state.Cycle, e.cfg)
	e.keyRotationBodies = make(map[[32]byte]*chain.KeyRotationEntry)
}

// KeyRotationValidator exposes the engine's key rotation validator.
func (e *Engine) KeyRotationValidator() *validation.KeyRotationValidator {
	return e.keyRotationValidator
}

// NodeUID returns a copy of the engine's node identity. It deliberately returns a copy
// so callers cannot mutate the engine's identity (or reach its secret key slice
// header) through the returned value.
func (e *Engine) NodeUID() identity.UIDZeroSoulbound {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.node.UID
}

// syncKeyRotationStateLocked refreshes the validator's view of the current cycle and
// validator set. State advances every cycle, and the validator set can change as
// peers join, so both must be re-synchronised before rotations are validated.
//
// The caller must hold e.mu.
func (e *Engine) syncKeyRotationStateLocked() {
	e.keyRotationValidator.SetValidatorSet(e.state.ValidatorSet)
	e.keyRotationValidator.SetCycle(e.state.Cycle)
}

// RotateKey builds, signs and submits a key rotation for this node's own validator.
//
// sigNew is the incoming key's Dilithium3 signature over the canonical rotation
// payload (see chain.KeyRotationPayloadFor). The engine signs the payload with the
// node's current secret key to satisfy rule 1 and never handles the incoming secret
// key, so a validator can rotate to a key held in an HSM or KMS.
//
// Keeping the outgoing secret key inside the engine means callers cannot read it out
// to sign for themselves.
//
// The caller must NOT hold e.mu.
func (e *Engine) RotateKey(
	ctx context.Context,
	newPublicKey [chain.KeyRotationPublicKeySize]byte,
	newVRFPublicKey [chain.KeyRotationVRFKeySize]byte,
	sigNew []byte,
	effectiveCycle, expiryCycle uint64,
) (*chain.KeyRotationEntry, error) {
	e.mu.Lock()
	submitter := e.node.UID.RootID
	secretKey := e.node.UID.SecretKey
	e.mu.Unlock()

	entry, err := chain.NewKeyRotationEntryWithNewSignature(
		submitter, secretKey, newPublicKey, newVRFPublicKey, sigNew,
		effectiveCycle, expiryCycle, time.Now().UnixNano(),
	)
	if err != nil {
		return nil, err
	}

	if err := e.SubmitKeyRotation(ctx, entry); err != nil {
		return entry, err
	}
	return entry, nil
}

// SubmitKeyRotation validates a key rotation entry and enqueues it for anchoring.
//
// The entry body is retained in memory because a ProvenanceEntry carries only the
// entry's hash and label; when the rotation is later anchored in a block the engine
// needs the full body in order to re-validate it and learn the new key. Peers learn
// the body out of band and register it via RecordRotationBody.
//
// The caller must NOT hold e.mu.
func (e *Engine) SubmitKeyRotation(_ context.Context, entry *chain.KeyRotationEntry) error {
	if entry == nil {
		return validation.ErrKeyRotationInvalidEntry
	}

	// Validate against the current cycle and validator set before queueing anything.
	e.mu.Lock()
	e.syncKeyRotationStateLocked()
	e.mu.Unlock()

	if err := e.keyRotationValidator.Validate(entry); err != nil {
		return err
	}

	e.mu.Lock()
	e.keyRotationBodies[entry.Hash] = entry
	e.mu.Unlock()

	return e.Enqueue(chain.ProvenanceEntry{
		Hash:      entry.Hash,
		Submitter: entry.Submitter,
		Timestamp: entry.Timestamp,
		Label:     entry.Label,
	})
}

// RecordRotationBody registers a key rotation body received from a peer so the engine
// can validate it once it is anchored. Bodies are keyed by entry hash.
//
// The caller must NOT hold e.mu.
func (e *Engine) RecordRotationBody(entry *chain.KeyRotationEntry) error {
	if entry == nil {
		return validation.ErrKeyRotationInvalidEntry
	}
	if !entry.VerifyHash() {
		return chain.ErrHashMismatch
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keyRotationBodies[entry.Hash] = entry
	return nil
}

// RotationBody returns a previously registered rotation body.
func (e *Engine) RotationBody(hash [32]byte) (*chain.KeyRotationEntry, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	body, ok := e.keyRotationBodies[hash]
	return body, ok
}

// processKeyRotationEntriesLocked admits every key rotation entry anchored in this
// cycle's batch, validating each against the five rules of §8.2 and folding accepted
// rotations into the key history.
//
// A rotation that fails validation is logged and skipped: it does not abort the
// cycle, because a malformed rotation must not be able to stall the chain.
//
// The caller must hold e.mu.
func (e *Engine) processKeyRotationEntriesLocked(entries []chain.ProvenanceEntry) {
	for _, pe := range entries {
		if pe.Label != chain.KeyRotationLabel {
			continue
		}

		body, ok := e.keyRotationBodies[pe.Hash]
		if !ok {
			log.Printf("IPC: key rotation %x anchored without a known body, ignoring", pe.Hash)
			continue
		}

		if err := e.keyRotationValidator.ValidateAndRecord(body); err != nil {
			log.Printf("IPC: rejecting key rotation from %x: %v", body.Submitter, err)
			continue
		}

		log.Printf("IPC: key rotation accepted for %x (effective=%d expiry=%d)",
			body.Submitter, body.EffectiveCycle, body.ExpiryCycle)
	}
}

// verifySignatureWithOverlap reports whether sig is a valid signature over msg from
// validatorID, considering every key authoritative for that validator in cycle.
//
// During a rotation's overlap window two keys are authoritative, so a message signed
// with either verifies. Outside the window only one is. Without this, a rotation would
// partition the network the moment it took effect.
//
// This method does not touch e.mu: the validator has its own lock, so callers that
// already hold the engine lock (RunCycle, RunPreparePhase) do not deadlock.
func (e *Engine) verifySignatureWithOverlap(validatorID [16]byte, msg, sig []byte, cycle uint64) bool {
	keys, err := e.keyRotationValidator.GetActivePublicKey(validatorID, cycle)
	if err != nil {
		return false
	}
	for _, pk := range keys {
		if identity.VerifyDilithium(pk[:], msg, sig) {
			return true
		}
	}
	return false
}

// keyRotationEpochLocked returns the greatest EffectiveCycle among accepted rotations
// that are already in force, which is the cycle a block's KeyRotationEpoch field should
// reference. Returns 0 when no rotation is in force.
//
// The caller must hold e.mu.
func (e *Engine) keyRotationEpochLocked() uint64 {
	cycle := e.state.Cycle
	var epoch uint64
	for _, vi := range e.state.ValidatorSet {
		for _, r := range e.keyRotationValidator.Rotations(vi.ValidatorID) {
			if r.IsEffective(cycle) && r.EffectiveCycle > epoch {
				epoch = r.EffectiveCycle
			}
		}
	}
	return epoch
}

// SyncKeyRotationState re-synchronises the key rotation validator with the engine's
// current cycle and validator set. Exported for callers that drive the engine's phases
// directly (tests, conformance harnesses) instead of via RunCycle.
func (e *Engine) SyncKeyRotationState() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.syncKeyRotationStateLocked()
}

// registerPeerValidatorSetLocked makes the peers' keys known to the key rotation
// validator. NewEngineWithPeers populates the validator set after newEngine has run,
// so the validator's snapshot has to be refreshed.
func (e *Engine) registerPeerValidatorSetLocked() {
	if e.keyRotationValidator == nil || len(e.peers) == 0 {
		return
	}
	set := make([]state.ValidatorInfo, 0, len(e.peers))
	for _, p := range e.peers {
		set = append(set, state.ValidatorInfo{
			ValidatorID:  p.UID.RootID,
			Dilithium3PK: p.UID.PublicKey,
			VRFPK:        p.UID.VRFPublicKey,
			ContractHash: p.UID.ContractHash,
		})
	}
	e.keyRotationValidator.SetValidatorSet(set)
}
