// Key rotation validation — 3CP v2.0 spec §8.2.
//
// A key-rotation-entry is valid iff all five rules below hold:
//
//  1. SignatureOld verifies against the submitter's active Dilithium3 public key.
//  2. SignatureNew verifies against NewPublicKey.
//  3. EffectiveCycle >= currentCycle + KeyRotationLeadTime.
//  4. ExpiryCycle    >= EffectiveCycle + MinKeyOverlap.
//  5. EffectiveCycle >  lastRotationCycle of the same validator.
//
// During [EffectiveCycle, ExpiryCycle] both the outgoing and the incoming key are
// accepted for signature verification, which is what lets a validator rotate without
// network downtime: peers that have not yet observed the rotation still verify
// messages signed with the old key, and vice versa.
package validation

import (
	"bytes"
	"fmt"
	"sort"
	"sync"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/state"
)

// KeyRotationValidator validates key rotation entries and resolves which public
// keys are authoritative for a validator in a given cycle.
//
// It is safe for concurrent use: RunCycle validates rotations while the PREPARE phase
// verifies signatures, and both paths reach this type. The validator therefore owns
// its own lock rather than borrowing the consensus engine's, so callers already
// holding the engine lock do not deadlock.
type KeyRotationValidator struct {
	mu           sync.RWMutex
	validators   map[[16]byte][chain.KeyRotationPublicKeySize]byte
	currentCycle uint64
	cfg          state.Config
	// rotations holds accepted rotations per validator, sorted ascending by
	// EffectiveCycle. Insertion order does not depend on the order entries happened
	// to be gossiped, so all nodes derive the same active key for a given cycle.
	rotations map[[16]byte][]*chain.KeyRotationEntry
}

// NewKeyRotationValidator creates a validator over a snapshot of the canonical
// validator set. currentCycle is the cycle used for rule 3 (lead time).
func NewKeyRotationValidator(validators []state.ValidatorInfo, currentCycle uint64, cfg state.Config) *KeyRotationValidator {
	v := &KeyRotationValidator{
		validators:   make(map[[16]byte][chain.KeyRotationPublicKeySize]byte, len(validators)),
		currentCycle: currentCycle,
		cfg:          cfg,
		rotations:    make(map[[16]byte][]*chain.KeyRotationEntry),
	}
	v.SetValidatorSet(validators)
	return v
}

// SetValidatorSet replaces the canonical validator set. Called each cycle by the
// consensus engine so that rule 1 resolves against the current key material.
func (v *KeyRotationValidator) SetValidatorSet(validators []state.ValidatorInfo) {
	m := make(map[[16]byte][chain.KeyRotationPublicKeySize]byte, len(validators))
	for _, vi := range validators {
		m[vi.ValidatorID] = vi.Dilithium3PK
	}
	v.mu.Lock()
	v.validators = m
	v.mu.Unlock()
}

// SetCycle updates the cycle used by rule 3 (lead time).
func (v *KeyRotationValidator) SetCycle(cycle uint64) {
	v.mu.Lock()
	v.currentCycle = cycle
	v.mu.Unlock()
}

// CurrentCycle returns the cycle against which lead time is measured.
func (v *KeyRotationValidator) CurrentCycle() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.currentCycle
}

// findValidatorByID returns the registered Dilithium3 public key for a validator.
func (v *KeyRotationValidator) findValidatorByID(id [16]byte) ([chain.KeyRotationPublicKeySize]byte, bool) {
	pk, ok := v.validators[id]
	return pk, ok
}

// lastRotationCycle returns the EffectiveCycle of the most recent accepted rotation
// for a validator, and whether any rotation has been recorded at all.
func (v *KeyRotationValidator) lastRotationCycle(id [16]byte) (uint64, bool) {
	entries := v.rotations[id]
	if len(entries) == 0 {
		return 0, false
	}
	// v.rotations[id] is kept sorted ascending by EffectiveCycle.
	return entries[len(entries)-1].EffectiveCycle, true
}

// LastRotationCycle exposes the last accepted EffectiveCycle for a validator.
func (v *KeyRotationValidator) LastRotationCycle(id [16]byte) (uint64, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastRotationCycle(id)
}

// Validate applies the five rules of spec §8.2. It does not mutate validator state;
// use RecordRotation (or ValidateAndRecord) to accept a rotation into the key history.
func (v *KeyRotationValidator) Validate(entry *chain.KeyRotationEntry) error {
	if entry == nil {
		return fmt.Errorf("%w: nil entry", ErrKeyRotationInvalidEntry)
	}
	if entry.Label != chain.KeyRotationLabel {
		return fmt.Errorf("%w: label %q", ErrKeyRotationInvalidEntry, entry.Label)
	}
	// Integrity: Hash must commit to the whole entry. The signatures already bind the
	// rotation-critical fields, so this is defence in depth against a body that was
	// altered after signing (e.g. Timestamp) and anchors a different digest than the
	// one that was validated.
	if !entry.VerifyHash() {
		return fmt.Errorf("%w: hash does not match entry contents", ErrKeyRotationInvalidEntry)
	}

	payloadBytes, err := entry.PayloadBytes()
	if err != nil {
		return fmt.Errorf("key rotation payload encoding: %w", err)
	}

	// Snapshot what the rules need, then release the lock: the two Dilithium3
	// verifications below are expensive and must not block other readers.
	registered, known := v.findValidatorByID(entry.Submitter)
	if !known {
		return fmt.Errorf("%w: %x", ErrUnknownSubmitter, entry.Submitter)
	}

	v.mu.RLock()
	currentCycle := v.currentCycle
	leadTime := v.cfg.KeyRotationLeadTime
	minOverlap := v.cfg.MinKeyOverlap
	lastCycle, hasPrevious := v.lastRotationCycle(entry.Submitter)
	v.mu.RUnlock()

	// Signature lengths are checked up front so a malformed entry reports the precise
	// problem instead of failing as a generic bad signature.
	if len(entry.SignatureOld) != chain.KeyRotationSignatureSize {
		return fmt.Errorf("%w: SignatureOld is %d bytes, want %d",
			ErrKeyRotationInvalidOldSig, len(entry.SignatureOld), chain.KeyRotationSignatureSize)
	}
	if len(entry.SignatureNew) != chain.KeyRotationSignatureSize {
		return fmt.Errorf("%w: SignatureNew is %d bytes, want %d",
			ErrKeyRotationInvalidNewSig, len(entry.SignatureNew), chain.KeyRotationSignatureSize)
	}

	// Rule 1: SignatureOld verifies against the submitter's active Dilithium3 key.
	//
	// "Active" means in force immediately before this rotation takes effect, not at
	// the current cycle. For a validator's first rotation those coincide with the
	// registered key; for a subsequent rotation they resolve to the previous
	// rotation's incoming key, which is what makes chained rotations possible. Rule 3
	// guarantees EffectiveCycle > currentCycle, so this never looks into the past.
	if !v.verifyAgainstActiveKeys(entry.Submitter, registered, authorisingCycle(entry), payloadBytes, entry.SignatureOld) {
		return ErrKeyRotationInvalidOldSig
	}

	// Rule 2: SignatureNew verifies against NewPublicKey. This proves the submitter
	// holds the incoming secret key.
	if !identity.VerifyDilithium(entry.NewPublicKey[:], payloadBytes, entry.SignatureNew) {
		return ErrKeyRotationInvalidNewSig
	}

	// Rule 3: EffectiveCycle >= currentCycle + KeyRotationLeadTime. The lead time
	// gives the network time to learn about the rotation before it takes effect.
	if entry.EffectiveCycle < currentCycle+leadTime {
		return fmt.Errorf("%w: effective=%d current=%d lead=%d",
			ErrKeyRotationLeadTime, entry.EffectiveCycle, currentCycle, leadTime)
	}

	// Rule 4: ExpiryCycle >= EffectiveCycle + MinKeyOverlap. The overlap is what
	// keeps the old key usable for a while after the new one takes over.
	if entry.ExpiryCycle < entry.EffectiveCycle+minOverlap {
		return fmt.Errorf("%w: expiry=%d effective=%d min_overlap=%d",
			ErrKeyRotationOverlap, entry.ExpiryCycle, entry.EffectiveCycle, minOverlap)
	}

	// Rule 5: EffectiveCycle > lastRotationCycle for this validator. Replaying or
	// backdating a rotation would let an attacker re-assert a key the network has
	// already moved past.
	if hasPrevious && entry.EffectiveCycle <= lastCycle {
		return fmt.Errorf("%w: effective=%d last=%d",
			ErrKeyRotationDuplicate, entry.EffectiveCycle, lastCycle)
	}

	return nil
}

// verifyAgainstActiveKeys reports whether sig verifies under any key that is
// authoritative for the validator in authorisingCycle.
func (v *KeyRotationValidator) verifyAgainstActiveKeys(
	id [16]byte,
	registered [chain.KeyRotationPublicKeySize]byte,
	authorisingCycle uint64,
	msg, sig []byte,
) bool {
	keys, err := v.GetActivePublicKey(id, authorisingCycle)
	if err != nil {
		// Unknown validator: fall back to the registered key so rule 1 can still run
		// (the caller reports ErrUnknownSubmitter separately).
		keys = [][chain.KeyRotationPublicKeySize]byte{registered}
	}
	for _, pk := range keys {
		if identity.VerifyDilithium(pk[:], msg, sig) {
			return true
		}
	}
	return false
}

// authorisingCycle returns the cycle whose active keys must authorise a rotation
// taking effect at effectiveCycle: the last cycle before it takes over.
func authorisingCycle(entry *chain.KeyRotationEntry) uint64 {
	if entry.EffectiveCycle == 0 {
		return 0
	}
	return entry.EffectiveCycle - 1
}

// ValidatorIDs returns the identifiers in the validator set, ordered.
//
// A light client needs this to ask which key is authoritative for each validator in a
// cycle. Exposing the set's membership rather than its keys is deliberate: the client
// holds the validator set as its own trust anchor and must not be handed key material it
// is supposed to be checking against.
func (v *KeyRotationValidator) ValidatorIDs() [][16]byte {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([][16]byte, 0, len(v.validators))
	for id := range v.validators {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i][:], out[j][:]) < 0
	})
	return out
}

// GetActivePublicKey returns the Dilithium3 public keys that are authoritative for a
// validator in the given cycle, in preference order.
//
//	cycle <  EffectiveCycle -> the outgoing key only
//	EffectiveCycle <= cycle <= ExpiryCycle -> both keys (overlap window)
//	cycle >  ExpiryCycle -> the incoming key only
//
// Consecutive rotations chain correctly: once a rotation's overlap window closes, its
// incoming key becomes the base that the next rotation builds on.
func (v *KeyRotationValidator) GetActivePublicKey(validatorID [16]byte, cycle uint64) ([][chain.KeyRotationPublicKeySize]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	current, ok := v.validators[validatorID]
	if !ok {
		return nil, fmt.Errorf("%w: %x", ErrUnknownSubmitter, validatorID)
	}

	for _, r := range v.rotations[validatorID] {
		if cycle < r.EffectiveCycle {
			break // rotations are sorted ascending: no later rotation applies yet
		}
		if r.InOverlap(cycle) {
			// Overlap: accept both so peers on either side of the rotation converge.
			return [][chain.KeyRotationPublicKeySize]byte{current, r.NewPublicKey}, nil
		}
		// Overlap closed: the incoming key is now the base for the next rotation.
		current = r.NewPublicKey
	}

	return [][chain.KeyRotationPublicKeySize]byte{current}, nil
}

// RecordRotation accepts an already-validated rotation into the key history,
// enforcing rule 5 against the recorded history. Re-recording a rotation, or one that
// is not strictly newer than the last accepted one, yields ErrKeyRotationDuplicate.
func (v *KeyRotationValidator) RecordRotation(entry *chain.KeyRotationEntry) error {
	if entry == nil {
		return fmt.Errorf("%w: nil entry", ErrKeyRotationInvalidEntry)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if last, ok := v.lastRotationCycle(entry.Submitter); ok && entry.EffectiveCycle <= last {
		return fmt.Errorf("%w: effective=%d last=%d",
			ErrKeyRotationDuplicate, entry.EffectiveCycle, last)
	}

	entries := v.rotations[entry.Submitter]
	// Keep ascending EffectiveCycle order regardless of arrival order.
	idx := sort.Search(len(entries), func(i int) bool {
		return entries[i].EffectiveCycle >= entry.EffectiveCycle
	})
	if idx < len(entries) && entries[idx].EffectiveCycle == entry.EffectiveCycle {
		return fmt.Errorf("%w: effective=%d", ErrKeyRotationDuplicate, entry.EffectiveCycle)
	}
	entries = append(entries, nil)
	copy(entries[idx+1:], entries[idx:])
	entries[idx] = entry
	v.rotations[entry.Submitter] = entries

	return nil
}

// ValidateAndRecord validates an entry against the five rules and, on success, accepts
// it into the key history. This is the path the consensus engine uses when it admits a
// rotation that arrived inside a block.
func (v *KeyRotationValidator) ValidateAndRecord(entry *chain.KeyRotationEntry) error {
	if err := v.Validate(entry); err != nil {
		return err
	}
	return v.RecordRotation(entry)
}

// Rotations returns the accepted rotations for a validator, ordered by EffectiveCycle.
func (v *KeyRotationValidator) Rotations(validatorID [16]byte) []*chain.KeyRotationEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*chain.KeyRotationEntry, len(v.rotations[validatorID]))
	copy(out, v.rotations[validatorID])
	return out
}
