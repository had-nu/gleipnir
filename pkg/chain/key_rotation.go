// IPC key rotation entries — 3CP v2.0 spec §8.
package chain

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/had-nu/gleipnir/pkg/identity"
	"lukechampine.com/blake3"
)

// Construction-time errors for key rotation entries. These cover malformed input to
// NewKeyRotationEntry and corrupt wire data; the protocol *rule* errors of spec §8.2
// live in pkg/validation (ErrKeyRotation*) so that there is exactly one canonical
// sentinel per rule.
var (
	// ErrInvalidCurrentKey is returned when the outgoing secret key is not a
	// well-formed Dilithium3 secret key.
	ErrInvalidCurrentKey = errors.New("3cp: invalid current Dilithium3 secret key")

	// ErrInvalidNewKey is returned when the incoming secret key is not a well-formed
	// Dilithium3 secret key.
	ErrInvalidNewKey = errors.New("3cp: invalid new Dilithium3 secret key")

	// ErrInvalidNewSig is returned when a caller-supplied SignatureNew is not a
	// Dilithium3 signature of the expected size.
	ErrInvalidNewSig = errors.New("3cp: invalid new key signature")

	// ErrSigningFailed is returned when signing a rotation payload yields no
	// signature of the expected size.
	ErrSigningFailed = errors.New("3cp: key rotation signing failed")

	// ErrHashMismatch is returned when a decoded entry's Hash does not commit to its
	// contents.
	ErrHashMismatch = errors.New("3cp: key rotation entry hash mismatch")
)

const (
	// KeyRotationLabel is the provenance entry label that identifies a key rotation
	// submission. Entries carrying this label are routed to the key rotation validator.
	KeyRotationLabel = "3cp:key-rotation:v1"

	// KeyRotationVRFKeySize is the size of a Ristretto255 VRF public key.
	KeyRotationVRFKeySize = 32
)

// Fixed sizes derived from the Dilithium3 implementation in use (pkg/identity, which
// wraps circl's round-3 mode3). They are exported so callers can validate wire input
// (e.g. gRPC requests) without importing pkg/identity.
//
// NOTE ON THE SPEC'S 2700-BYTE SIGNATURE: 3CP v2.0 §8.1 declares SignatureOld and
// SignatureNew as `bytes .size 2700`, but no Dilithium3 parameter set produces a
// 2700-byte signature. FIPS 204 defines 2420 (ML-DSA-44), 3309 (ML-DSA-65) and 4627
// (ML-DSA-87); the 1952-byte public key this codebase uses is circl round-3 mode3's,
// whose signatures are 3293 bytes (secret keys 4000). The sizes below are therefore
// sourced from pkg/identity, the single source of truth, rather than hard-coded — a
// future switch to a FIPS 204 conformant Dilithium changes one place. Because the
// spec's fixed size is unachievable, the signature fields are byte strings rather than
// fixed-size arrays: a [2700]byte field would silently truncate every real signature
// and make every rotation fail verification.
const (
	KeyRotationPublicKeySize = identity.Dilithium3PublicKeySize // 1952 bytes
	KeyRotationSecretKeySize = identity.Dilithium3SecretKeySize // 4000 bytes
	KeyRotationSignatureSize = identity.Dilithium3SignatureSize // 3293 bytes
)

// KeyRotationEntry is a validator's request to rotate its Dilithium3 signing key and
// its VRF key, per 3CP v2.0 spec §8.1.
//
// A rotation is authorised only when it is signed by BOTH the outgoing key
// (SignatureOld) and the incoming key (SignatureNew). Requiring the incoming
// signature proves the submitter possesses the new secret key, which is what stops
// anyone else from locking a validator out of its own identity.
//
// The entry is anchored as a regular provenance entry with Label == KeyRotationLabel;
// Hash commits to every field, so EffectiveCycle/ExpiryCycle cannot be tampered with
// after submission.
type KeyRotationEntry struct {
	Hash            [32]byte   `cbor:"0,keyasint"`
	Submitter       [16]byte   `cbor:"1,keyasint"`
	Timestamp       int64      `cbor:"2,keyasint"`
	Label           string     `cbor:"3,keyasint"` // always KeyRotationLabel
	NewPublicKey    [1952]byte `cbor:"20,keyasint"`
	NewVRFPublicKey [32]byte   `cbor:"21,keyasint"`
	EffectiveCycle  uint64     `cbor:"22,keyasint"`
	ExpiryCycle     uint64     `cbor:"23,keyasint"`
	// SignatureOld and SignatureNew are byte strings, not fixed-size arrays — see the
	// note on KeyRotationSignatureSize for why the spec's 2700-byte size is not usable.
	// Validate rejects any entry whose signatures are not exactly
	// KeyRotationSignatureSize bytes.
	SignatureOld []byte `cbor:"24,keyasint"`
	SignatureNew []byte `cbor:"25,keyasint"`
}

// KeyRotationPayload is the exact byte string covered by SignatureOld and
// SignatureNew (3CP v2.0 spec §8.2 rules 1 and 2).
//
// It deliberately excludes Hash, Timestamp and the signatures themselves: those are
// derived from, or cover, this payload, so including them would be circular. The
// label is pinned to KeyRotationLabel, which prevents a signed rotation payload from
// being replayed as some other kind of entry.
type KeyRotationPayload struct {
	Label           string     `cbor:"0,keyasint"`
	Submitter       [16]byte   `cbor:"1,keyasint"`
	NewPublicKey    [1952]byte `cbor:"2,keyasint"`
	NewVRFPublicKey [32]byte   `cbor:"3,keyasint"`
	EffectiveCycle  uint64     `cbor:"4,keyasint"`
	ExpiryCycle     uint64     `cbor:"5,keyasint"`
}

// Payload returns the payload covered by the rotation signatures.
func (k *KeyRotationEntry) Payload() KeyRotationPayload {
	return KeyRotationPayload{
		Label:           KeyRotationLabel,
		Submitter:       k.Submitter,
		NewPublicKey:    k.NewPublicKey,
		NewVRFPublicKey: k.NewVRFPublicKey,
		EffectiveCycle:  k.EffectiveCycle,
		ExpiryCycle:     k.ExpiryCycle,
	}
}

// PayloadBytes returns the canonical CBOR encoding of the rotation payload. Canonical
// CBOR is required (rather than a hand-rolled concatenation) so that signer and
// verifier cannot disagree on field order or integer width.
func (k *KeyRotationEntry) PayloadBytes() ([]byte, error) {
	payload := k.Payload()
	return deterministicMode.Marshal(&payload)
}

// ComputeHash returns the BLAKE3-256 digest of the entry, computed with Hash itself
// zeroed so the digest is a fixed point of the construction.
func (k *KeyRotationEntry) ComputeHash() [32]byte {
	clone := *k
	clone.Hash = [32]byte{}
	encoded, err := deterministicMode.Marshal(&clone)
	if err != nil {
		return [32]byte{}
	}
	return blake3.Sum256(encoded)
}

// VerifyHash reports whether Hash matches the recomputed digest of the entry.
func (k *KeyRotationEntry) VerifyHash() bool {
	return k.Hash == k.ComputeHash()
}

// InOverlap reports whether cycle falls inside [EffectiveCycle, ExpiryCycle], the
// window during which both the outgoing and the incoming key are accepted.
func (k *KeyRotationEntry) InOverlap(cycle uint64) bool {
	return cycle >= k.EffectiveCycle && cycle <= k.ExpiryCycle
}

// IsEffective reports whether the incoming key is already in force at cycle.
func (k *KeyRotationEntry) IsEffective(cycle uint64) bool {
	return cycle >= k.EffectiveCycle
}

// NewKeyRotationEntry builds a fully signed key rotation entry.
//
// newSecretKey signs the payload with the incoming key (rule 2). It is required: a
// rotation whose new key has never proved possession is not a rotation, it is a
// unilateral key change that can lock the validator out.
//
// The temporal rules (spec §8.2 rules 3-5: lead time, minimum overlap, no duplicate
// rotation) are intentionally NOT enforced here. They are enforced by
// validation.KeyRotationValidator.Validate, which owns the canonical error sentinels
// and the view of the current cycle and validator set. Enforcing them in both places
// would duplicate the policy and require pkg/chain to import pkg/validation, which
// imports pkg/chain — an import cycle.
func NewKeyRotationEntry(
	submitter [16]byte,
	currentSecretKey []byte,
	newPublicKey [KeyRotationPublicKeySize]byte,
	newVRFPublicKey [KeyRotationVRFKeySize]byte,
	newSecretKey []byte,
	effectiveCycle, expiryCycle uint64,
	timestamp int64,
) (*KeyRotationEntry, error) {
	if len(newSecretKey) != KeyRotationSecretKeySize {
		return nil, ErrInvalidNewKey
	}
	entry := newRotationEntryShell(submitter, newPublicKey, newVRFPublicKey,
		effectiveCycle, expiryCycle, timestamp)

	payloadBytes, err := entry.PayloadBytes()
	if err != nil {
		return nil, err
	}

	// Rule 2: incoming key proves possession of itself.
	sigNew := identity.SignDilithium(newSecretKey, payloadBytes)
	if len(sigNew) != KeyRotationSignatureSize {
		return nil, ErrSigningFailed
	}
	entry.SignatureNew = sigNew

	if err := signRotationWithCurrentKey(entry, currentSecretKey); err != nil {
		return nil, err
	}
	return entry, nil
}

// NewKeyRotationEntryWithNewSignature assembles a rotation when the incoming key is
// held elsewhere (an HSM, a KMS, or the caller's own process) and therefore cannot be
// used to sign here.
//
// sigNew must be the incoming key's Dilithium3 signature over the entry's canonical
// payload. It is verified by validation.KeyRotationValidator.Validate as rule 2, so a
// wrong or forged signature is rejected rather than trusted. Callers can produce the
// payload with KeyRotationPayloadFor without holding a secret key.
//
// This is the constructor the gRPC SubmitKeyRotation endpoint uses: the server holds
// only the outgoing key, so rule 1 is satisfied locally while rule 2 is satisfied by
// the client.
func NewKeyRotationEntryWithNewSignature(
	submitter [16]byte,
	currentSecretKey []byte,
	newPublicKey [KeyRotationPublicKeySize]byte,
	newVRFPublicKey [KeyRotationVRFKeySize]byte,
	sigNew []byte,
	effectiveCycle, expiryCycle uint64,
	timestamp int64,
) (*KeyRotationEntry, error) {
	entry := newRotationEntryShell(submitter, newPublicKey, newVRFPublicKey,
		effectiveCycle, expiryCycle, timestamp)
	if len(sigNew) != KeyRotationSignatureSize {
		return nil, ErrInvalidNewSig
	}
	entry.SignatureNew = append([]byte(nil), sigNew...)

	if err := signRotationWithCurrentKey(entry, currentSecretKey); err != nil {
		return nil, err
	}
	return entry, nil
}

// KeyRotationPayloadFor returns the canonical payload that both rotation signatures
// must cover. Callers that hold the incoming secret key can use it to produce sigNew
// without building a full entry.
func KeyRotationPayloadFor(
	submitter [16]byte,
	newPublicKey [KeyRotationPublicKeySize]byte,
	newVRFPublicKey [KeyRotationVRFKeySize]byte,
	effectiveCycle, expiryCycle uint64,
) ([]byte, error) {
	entry := &KeyRotationEntry{
		Submitter:       submitter,
		Label:           KeyRotationLabel,
		NewPublicKey:    newPublicKey,
		NewVRFPublicKey: newVRFPublicKey,
		EffectiveCycle:  effectiveCycle,
		ExpiryCycle:     expiryCycle,
	}
	return entry.PayloadBytes()
}

// newRotationEntryShell builds the unsigned part of a rotation entry.
func newRotationEntryShell(
	submitter [16]byte,
	newPublicKey [KeyRotationPublicKeySize]byte,
	newVRFPublicKey [KeyRotationVRFKeySize]byte,
	effectiveCycle, expiryCycle uint64,
	timestamp int64,
) *KeyRotationEntry {
	return &KeyRotationEntry{
		Submitter:       submitter,
		Timestamp:       timestamp,
		Label:           KeyRotationLabel,
		NewPublicKey:    newPublicKey,
		NewVRFPublicKey: newVRFPublicKey,
		EffectiveCycle:  effectiveCycle,
		ExpiryCycle:     expiryCycle,
	}
}

// signRotationWithCurrentKey applies rule 1 and commits the entry hash.
func signRotationWithCurrentKey(entry *KeyRotationEntry, currentSecretKey []byte) error {
	if len(currentSecretKey) != KeyRotationSecretKeySize {
		return ErrInvalidCurrentKey
	}

	payloadBytes, err := entry.PayloadBytes()
	if err != nil {
		return err
	}

	// Rule 1: outgoing key authorises the rotation.
	sigOld := identity.SignDilithium(currentSecretKey, payloadBytes)
	if len(sigOld) != KeyRotationSignatureSize {
		return ErrSigningFailed
	}
	entry.SignatureOld = sigOld

	entry.Hash = entry.ComputeHash()
	return nil
}

// MarshalKeyRotationEntry encodes a key rotation entry to canonical CBOR.
func MarshalKeyRotationEntry(k *KeyRotationEntry) ([]byte, error) {
	return deterministicMode.Marshal(k)
}

// UnmarshalKeyRotationEntry decodes a key rotation entry from canonical CBOR and
// verifies that Hash commits to the decoded contents.
func UnmarshalKeyRotationEntry(data []byte) (*KeyRotationEntry, error) {
	var k KeyRotationEntry
	if err := cbor.Unmarshal(data, &k); err != nil {
		return nil, err
	}
	if !k.VerifyHash() {
		return nil, ErrHashMismatch
	}
	return &k, nil
}
