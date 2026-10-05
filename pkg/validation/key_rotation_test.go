// Key rotation conformance tests — 3CP v2.0 spec §8.2 and §16.
//
// Test IDs follow SPEC §16:
//
//	TC-ROT-01  valid key rotation; both keys accepted across the overlap window
//	TC-ROT-02  rotation with too-early EffectiveCycle is rejected
package validation

import (
	"errors"
	"testing"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/state"
)

// testRotationValidator bundles a validator under test with the key material needed
// to build correctly signed rotations for it.
type testRotationValidator struct {
	validator *KeyRotationValidator
	id        [16]byte
	oldPK     [chain.KeyRotationPublicKeySize]byte
	oldSK     []byte
	newPK     [chain.KeyRotationPublicKeySize]byte
	newSK     []byte
	newVRFPK  [chain.KeyRotationVRFKeySize]byte
}

// newTestRotationValidator builds a single-validator network whose current key is
// derived deterministically from seed. Deterministic seeds keep the tests reproducible;
// the signatures themselves are real Dilithium3 signatures.
func newTestRotationValidator(t *testing.T, currentCycle uint64) *testRotationValidator {
	t.Helper()

	var id [16]byte
	copy(id[:], []byte("rot-validator-01"))

	oldPK, oldSK, err := identity.GenerateDilithiumKeyFromSeed(seed(1))
	if err != nil {
		t.Fatalf("generate current key: %v", err)
	}
	newPK, newSK, err := identity.GenerateDilithiumKeyFromSeed(seed(2))
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}

	var newVRFPK [chain.KeyRotationVRFKeySize]byte
	copy(newVRFPK[:], seed(3))

	return &testRotationValidator{
		validator: NewKeyRotationValidator(
			[]state.ValidatorInfo{{
				ValidatorID:  id,
				Dilithium3PK: oldPK,
				VRFPK:        newVRFPK,
			}},
			currentCycle,
			state.DefaultConfig,
		),
		id:       id,
		oldPK:    oldPK,
		oldSK:    oldSK,
		newPK:    newPK,
		newSK:    newSK,
		newVRFPK: newVRFPK,
	}
}

// seed returns a 32-byte deterministic seed (Dilithium3 seed size) for test n.
func seed(n byte) []byte {
	s := make([]byte, identity.Dilithium3SeedSize)
	for i := range s {
		s[i] = n*7 + byte(i)
	}
	return s
}

// rotation builds a correctly signed rotation with the given schedule.
func (tv *testRotationValidator) rotation(t *testing.T, effective, expiry uint64) *chain.KeyRotationEntry {
	t.Helper()
	entry, err := chain.NewKeyRotationEntry(
		tv.id, tv.oldSK, tv.newPK, tv.newVRFPK, tv.newSK,
		effective, expiry, 1700000000000000000,
	)
	if err != nil {
		t.Fatalf("NewKeyRotationEntry: %v", err)
	}
	return entry
}

// TestKeyRotationValidation exercises each of the five rules of spec §8.2 in isolation.
func TestKeyRotationValidation(t *testing.T) {
	const currentCycle = 100
	cfg := state.DefaultConfig // KeyRotationLeadTime=10, MinKeyOverlap=10

	t.Run("ValidRotation", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, currentCycle+cfg.KeyRotationLeadTime,
			currentCycle+cfg.KeyRotationLeadTime+cfg.MinKeyOverlap)

		if err := tv.validator.Validate(entry); err != nil {
			t.Fatalf("expected valid rotation to pass, got %v", err)
		}
		if !entry.VerifyHash() {
			t.Fatal("entry hash must commit to entry contents")
		}
	})

	// Rule 1: SignatureOld must verify under the submitter's active Dilithium3 key.
	t.Run("InvalidOldSignature", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 120)
		entry.SignatureOld = make([]byte, chain.KeyRotationSignatureSize)
		entry.Hash = entry.ComputeHash()

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationInvalidOldSig)
	})

	t.Run("TruncatedOldSignature", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 120)
		entry.SignatureOld = entry.SignatureOld[:100]
		entry.Hash = entry.ComputeHash()

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationInvalidOldSig)
	})

	// Rule 1 again, from the other direction: a signature made by a key that is not
	// the validator's must not authorise a rotation of that validator.
	t.Run("OldSignatureFromForeignKey", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		_, foreignSK, err := identity.GenerateDilithiumKeyFromSeed(seed(9))
		if err != nil {
			t.Fatalf("generate foreign key: %v", err)
		}

		entry := tv.rotation(t, 110, 120)
		payloadBytes, err := entry.PayloadBytes()
		if err != nil {
			t.Fatalf("PayloadBytes: %v", err)
		}

		entry.SignatureOld = identity.SignDilithium(foreignSK, payloadBytes)
		entry.Hash = entry.ComputeHash() // re-commit so only rule 1 can fail

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationInvalidOldSig)
	})

	// Rule 2: SignatureNew must verify under NewPublicKey, proving the submitter
	// holds the incoming secret key.
	t.Run("InvalidNewSignature", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 120)
		entry.SignatureNew = make([]byte, chain.KeyRotationSignatureSize)
		entry.Hash = entry.ComputeHash()

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationInvalidNewSig)
	})

	t.Run("NewSignatureFromWrongKey", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 120)

		// Swap in a signature made by the OLD key: proves the new key must sign too.
		payloadBytes, err := entry.PayloadBytes()
		if err != nil {
			t.Fatalf("PayloadBytes: %v", err)
		}
		entry.SignatureNew = identity.SignDilithium(tv.oldSK, payloadBytes)
		entry.Hash = entry.ComputeHash()

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationInvalidNewSig)
	})

	// Rule 3: EffectiveCycle must respect the lead time.
	t.Run("EffectiveCycleTooEarly", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 105, 120) // min is 100+10=110

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationLeadTime)
	})

	t.Run("EffectiveCycleAtLeadTimeBoundary", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, currentCycle+cfg.KeyRotationLeadTime, 120)

		if err := tv.validator.Validate(entry); err != nil {
			t.Fatalf("rotation exactly at the lead-time boundary must be valid, got %v", err)
		}
	})

	// Rule 4: the overlap window must be at least MinKeyOverlap cycles long.
	t.Run("InsufficientOverlap", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 115) // 115-110 = 5 < MinKeyOverlap(10)

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationOverlap)
	})

	t.Run("OverlapAtBoundary", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 110+cfg.MinKeyOverlap)

		if err := tv.validator.Validate(entry); err != nil {
			t.Fatalf("rotation with exactly MinKeyOverlap must be valid, got %v", err)
		}
	})

	// Rule 5: a rotation must be strictly newer than the last accepted one.
	t.Run("DuplicateRotation", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		// Record a rotation far enough ahead that a later entry can be backdated to a
		// cycle that still satisfies rule 3, isolating rule 5 from rule 3.
		first := tv.rotation(t, 130, 140)
		if err := tv.validator.ValidateAndRecord(first); err != nil {
			t.Fatalf("record first rotation: %v", err)
		}

		// Replaying the same schedule is a duplicate.
		replay := tv.rotation(t, 130, 140)
		assertErrIs(t, tv.validator.Validate(replay), ErrKeyRotationDuplicate)

		// Backdating to a cycle that respects the lead time is still rejected: it is not
		// strictly newer than the rotation already recorded.
		backdated := tv.rotation(t, 110, 150)
		assertErrIs(t, tv.validator.Validate(backdated), ErrKeyRotationDuplicate)
	})

	t.Run("RecordRotationRejectsDuplicate", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		first := tv.rotation(t, 110, 120)
		if err := tv.validator.RecordRotation(first); err != nil {
			t.Fatalf("record first rotation: %v", err)
		}
		if err := tv.validator.RecordRotation(first); !errors.Is(err, ErrKeyRotationDuplicate) {
			t.Fatalf("expected ErrKeyRotationDuplicate on re-record, got %v", err)
		}
	})

	t.Run("UnknownSubmitter", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 120)

		var stranger [16]byte
		copy(stranger[:], []byte("not-a-validator"))
		entry.Submitter = stranger
		entry.Hash = entry.ComputeHash()

		assertErrIs(t, tv.validator.Validate(entry), ErrUnknownSubmitter)
	})

	t.Run("WrongLabelRejected", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 120)
		entry.Label = "3cp:some-other:v1"
		entry.Hash = entry.ComputeHash()

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationInvalidEntry)
	})

	// A body altered after signing must not pass the hash integrity check.
	t.Run("TamperedEntryRejected", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		entry := tv.rotation(t, 110, 120)
		entry.Timestamp += 1 // not covered by the rotation signatures

		assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationInvalidEntry)
	})

	t.Run("NilEntryRejected", func(t *testing.T) {
		tv := newTestRotationValidator(t, currentCycle)
		assertErrIs(t, tv.validator.Validate(nil), ErrKeyRotationInvalidEntry)
	})
}

// TC-ROT-01: a valid rotation is accepted, and both the outgoing and the incoming key
// verify throughout the overlap window. After the window closes only the new key is
// active; before it opens only the old key is.
func TestKeyRotationOverlapPeriod(t *testing.T) {
	const currentCycle = 100
	cfg := state.DefaultConfig

	tv := newTestRotationValidator(t, currentCycle)
	entry := tv.rotation(t, 110, 120)

	if err := tv.validator.Validate(entry); err != nil {
		t.Fatalf("TC-ROT-01: valid rotation must validate: %v", err)
	}
	if err := tv.validator.RecordRotation(entry); err != nil {
		t.Fatalf("TC-ROT-01: record rotation: %v", err)
	}

	// Before EffectiveCycle: only the outgoing key.
	keys, err := tv.validator.GetActivePublicKey(entry.Submitter, entry.EffectiveCycle-1)
	if err != nil {
		t.Fatalf("TC-ROT-01: GetActivePublicKey: %v", err)
	}
	if len(keys) != 1 || keys[0] != tv.oldPK {
		t.Fatalf("TC-ROT-01: before EffectiveCycle want [old key], got %d keys", len(keys))
	}

	// Throughout [EffectiveCycle, ExpiryCycle]: both keys are accepted.
	msg := []byte("consensus message signed during key overlap")
	sigOld := identity.SignDilithium(tv.oldSK, msg)
	sigNew := identity.SignDilithium(tv.newSK, msg)
	if len(sigOld) != chain.KeyRotationSignatureSize || len(sigNew) != chain.KeyRotationSignatureSize {
		t.Fatalf("signature size mismatch: old=%d new=%d want=%d",
			len(sigOld), len(sigNew), chain.KeyRotationSignatureSize)
	}

	for cycle := entry.EffectiveCycle; cycle <= entry.ExpiryCycle; cycle++ {
		keys, err := tv.validator.GetActivePublicKey(entry.Submitter, cycle)
		if err != nil {
			t.Fatalf("TC-ROT-01: GetActivePublicKey(cycle=%d): %v", cycle, err)
		}
		if len(keys) != 2 {
			t.Fatalf("TC-ROT-01: cycle %d: want 2 active keys in overlap, got %d", cycle, len(keys))
		}
		if keys[0] != tv.oldPK || keys[1] != tv.newPK {
			t.Fatalf("TC-ROT-01: cycle %d: active keys must be [old, new]", cycle)
		}
		// Both signatures must verify against the returned key set.
		if !verifyAny(keys, msg, sigOld) {
			t.Fatalf("TC-ROT-01: cycle %d: old-key signature rejected during overlap", cycle)
		}
		if !verifyAny(keys, msg, sigNew) {
			t.Fatalf("TC-ROT-01: cycle %d: new-key signature rejected during overlap", cycle)
		}
	}

	// After ExpiryCycle: only the incoming key, and the old signature is rejected.
	keys, err = tv.validator.GetActivePublicKey(entry.Submitter, entry.ExpiryCycle+1)
	if err != nil {
		t.Fatalf("TC-ROT-01: GetActivePublicKey: %v", err)
	}
	if len(keys) != 1 || keys[0] != tv.newPK {
		t.Fatalf("TC-ROT-01: after ExpiryCycle want [new key], got %d keys", len(keys))
	}
	if verifyAny(keys, msg, sigOld) {
		t.Fatal("TC-ROT-01: old-key signature must not verify after the overlap closes")
	}
	if !verifyAny(keys, msg, sigNew) {
		t.Fatal("TC-ROT-01: new-key signature must verify after the overlap closes")
	}

	// Sanity: the schedule honours the configured lead time and overlap.
	if entry.EffectiveCycle < currentCycle+cfg.KeyRotationLeadTime {
		t.Fatalf("test fixture violates lead time: effective=%d", entry.EffectiveCycle)
	}
	if entry.ExpiryCycle-entry.EffectiveCycle < cfg.MinKeyOverlap {
		t.Fatalf("test fixture violates MinKeyOverlap: effective=%d expiry=%d",
			entry.EffectiveCycle, entry.ExpiryCycle)
	}
}

// TC-ROT-02: a rotation whose EffectiveCycle is inside the lead time is rejected, so
// peers cannot be given insufficient notice to learn the new key.
func TestKeyRotationEarlyEffectiveCycle(t *testing.T) {
	const currentCycle = 100

	tv := newTestRotationValidator(t, currentCycle)
	entry := tv.rotation(t, 105, 120) // too early: min is currentCycle+10=110

	err := tv.validator.Validate(entry)
	if !errors.Is(err, ErrKeyRotationLeadTime) {
		t.Fatalf("TC-ROT-02: want ErrKeyRotationLeadTime, got %v", err)
	}

	// ValidateAndRecord is the engine's admission path: it must reject the rotation
	// and leave no trace in the key history.
	if err := tv.validator.ValidateAndRecord(entry); !errors.Is(err, ErrKeyRotationLeadTime) {
		t.Fatalf("TC-ROT-02: ValidateAndRecord must reject an early rotation, got %v", err)
	}
	if got := len(tv.validator.Rotations(entry.Submitter)); got != 0 {
		t.Fatalf("TC-ROT-02: rejected rotation must not be recorded, found %d", got)
	}

	// The same schedule is accepted once it respects the lead time.
	ok := tv.rotation(t, 110, 120)
	if err := tv.validator.ValidateAndRecord(ok); err != nil {
		t.Fatalf("TC-ROT-02: rotation respecting lead time must be accepted, got %v", err)
	}
}

// Consecutive rotations chain: once the first overlap closes, its incoming key
// becomes the base key the next rotation builds on.
func TestKeyRotationChainedRotations(t *testing.T) {
	const currentCycle = 100

	tv := newTestRotationValidator(t, currentCycle)
	first := tv.rotation(t, 110, 120)
	if err := tv.validator.ValidateAndRecord(first); err != nil {
		t.Fatalf("record first rotation: %v", err)
	}

	// The second rotation is signed by the first rotation's incoming key.
	thirdPK, thirdSK, err := identity.GenerateDilithiumKeyFromSeed(seed(3))
	if err != nil {
		t.Fatalf("generate third key: %v", err)
	}
	second, err := chain.NewKeyRotationEntry(
		tv.id, tv.newSK, thirdPK, first.NewVRFPublicKey, thirdSK,
		130, 140, 1700000000000000001,
	)
	if err != nil {
		t.Fatalf("build second rotation: %v", err)
	}
	if err := tv.validator.ValidateAndRecord(second); err != nil {
		t.Fatalf("record second rotation: %v", err)
	}

	// Cycle 125: first rotation has expired, so its new key is the sole active key.
	keys, err := tv.validator.GetActivePublicKey(tv.id, 125)
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(keys) != 1 || keys[0] != tv.newPK {
		t.Fatal("cycle 125: want the first rotation's new key as the active key")
	}

	// Cycle 135: second rotation in its overlap, so [first-new, second-new].
	keys, err = tv.validator.GetActivePublicKey(tv.id, 135)
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(keys) != 2 || keys[0] != tv.newPK || keys[1] != thirdPK {
		t.Fatal("cycle 135: want [first-new, second-new] during the second overlap")
	}

	// Cycle 141: only the second rotation's new key remains active.
	keys, err = tv.validator.GetActivePublicKey(tv.id, 141)
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(keys) != 1 || keys[0] != thirdPK {
		t.Fatal("cycle 141: want only the second rotation's new key")
	}

	// The first rotation's new key still authorises a further rotation after the
	// overlap closed, because it is the validator's active key at the current cycle.
	if _, ok := tv.validator.LastRotationCycle(tv.id); !ok {
		t.Fatal("expected a recorded last rotation cycle")
	}
	if got, _ := tv.validator.LastRotationCycle(tv.id); got != 130 {
		t.Fatalf("want last rotation cycle 130, got %d", got)
	}
}

// A rotation survives canonical CBOR round-tripping with its hash intact, and a
// tampered body is rejected on decode.
func TestKeyRotationCBORRoundTrip(t *testing.T) {
	tv := newTestRotationValidator(t, 100)
	entry := tv.rotation(t, 110, 120)

	encoded, err := chain.MarshalKeyRotationEntry(entry)
	if err != nil {
		t.Fatalf("MarshalKeyRotationEntry: %v", err)
	}

	decoded, err := chain.UnmarshalKeyRotationEntry(encoded)
	if err != nil {
		t.Fatalf("UnmarshalKeyRotationEntry: %v", err)
	}
	if decoded.Hash != entry.Hash {
		t.Fatal("round-trip must preserve the entry hash")
	}
	if decoded.NewPublicKey != entry.NewPublicKey || decoded.EffectiveCycle != entry.EffectiveCycle {
		t.Fatal("round-trip must preserve rotation fields")
	}
	if err := tv.validator.Validate(decoded); err != nil {
		t.Fatalf("decoded entry must still validate: %v", err)
	}

	// Tamper with the encoded body: the hash check must reject it.
	tampered := *decoded
	tampered.EffectiveCycle = 500
	tamperedBytes, err := chain.MarshalKeyRotationEntry(&tampered)
	if err != nil {
		t.Fatalf("MarshalKeyRotationEntry(tampered): %v", err)
	}
	if _, err := chain.UnmarshalKeyRotationEntry(tamperedBytes); !errors.Is(err, chain.ErrHashMismatch) {
		t.Fatalf("want chain.ErrHashMismatch on tampered body, got %v", err)
	}
}

// NewKeyRotationEntry rejects malformed secret keys and produces a hash that commits
// to the signed fields.
func TestNewKeyRotationEntryValidation(t *testing.T) {
	tv := newTestRotationValidator(t, 100)

	t.Run("MissingCurrentKey", func(t *testing.T) {
		_, err := chain.NewKeyRotationEntry(tv.id, nil, tv.newPK, tv.newVRFPK, tv.newSK, 110, 120, 1)
		if !errors.Is(err, chain.ErrInvalidCurrentKey) {
			t.Fatalf("want chain.ErrInvalidCurrentKey, got %v", err)
		}
	})

	t.Run("MissingNewKey", func(t *testing.T) {
		// Without the incoming secret key the submitter cannot prove possession of the
		// new key, so the rotation must not be constructible.
		_, err := chain.NewKeyRotationEntry(tv.id, tv.oldSK, tv.newPK, tv.newVRFPK, nil, 110, 120, 1)
		if !errors.Is(err, chain.ErrInvalidNewKey) {
			t.Fatalf("want chain.ErrInvalidNewKey, got %v", err)
		}
	})

	t.Run("HashCommitsToEntry", func(t *testing.T) {
		entry := tv.rotation(t, 110, 120)
		if !entry.VerifyHash() {
			t.Fatal("freshly built entry must have a matching hash")
		}
		mutated := *entry
		mutated.EffectiveCycle = 111
		if mutated.VerifyHash() {
			t.Fatal("changing EffectiveCycle must invalidate the hash")
		}
	})
}

// GetActivePublicKey on an unknown validator reports ErrUnknownSubmitter.
func TestGetActivePublicKeyUnknownValidator(t *testing.T) {
	tv := newTestRotationValidator(t, 100)

	var stranger [16]byte
	copy(stranger[:], []byte("stranger"))

	if _, err := tv.validator.GetActivePublicKey(stranger, 110); !errors.Is(err, ErrUnknownSubmitter) {
		t.Fatalf("want ErrUnknownSubmitter, got %v", err)
	}
}

// The validator tracks the cycle and validator set changes made by the engine.
func TestKeyRotationValidatorStateUpdates(t *testing.T) {
	tv := newTestRotationValidator(t, 100)

	tv.validator.SetCycle(500)
	if got := tv.validator.CurrentCycle(); got != 500 {
		t.Fatalf("want cycle 500, got %d", got)
	}

	// A rotation built for the old cycle is now inside the lead-time window.
	entry := tv.rotation(t, 110, 120)
	assertErrIs(t, tv.validator.Validate(entry), ErrKeyRotationLeadTime)

	// Dropping the validator from the set makes it unknown.
	tv.validator.SetValidatorSet(nil)
	assertErrIs(t, tv.validator.Validate(entry), ErrUnknownSubmitter)
}

// verifyAny reports whether sig verifies under any of the given public keys.
func verifyAny(keys [][chain.KeyRotationPublicKeySize]byte, msg, sig []byte) bool {
	for _, k := range keys {
		if identity.VerifyDilithium(k[:], msg, sig) {
			return true
		}
	}
	return false
}

// assertErrIs fails unless err wraps want.
func assertErrIs(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
}
