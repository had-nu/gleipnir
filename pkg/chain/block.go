// IPC block and entry types — 3CP v2.0.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/fxamacker/cbor/v2"
	"lukechampine.com/blake3"
)

// Block represents a block in the 3CP chain v2.0.
type Block struct {
	Index     uint64            `cbor:"0,keyasint"`
	PrevHash  []byte            `cbor:"1,keyasint"`
	StateRoot []byte            `cbor:"2,keyasint"`
	Proposer  [16]byte          `cbor:"3,keyasint"`
	Anchored  []ProvenanceEntry `cbor:"4,keyasint"`
	Lambda1   float64           `cbor:"5,keyasint"`
	Timestamp int64             `cbor:"6,keyasint"`
	Quorum    QuorumConfig      `cbor:"7,keyasint"`
	BlockHash []byte            `cbor:"8,keyasint"`

	// v2.0 fields (MUST in v2 networks)
	ProtocolVersion   uint16            `cbor:"9,keyasint"`  // default: 2
	PrepareSigsBitmap []byte            `cbor:"10,keyasint"` // bitfield, N bits
	PrepareSigs       [][]byte          `cbor:"11,keyasint"` // only active signers' signatures
	CommitSig         []byte            `cbor:"12,keyasint"` // leader's COMMIT signature (identity.Dilithium3SignatureSize bytes)
	ExternalAnchors   []string          `cbor:"13,keyasint"` // URIs/CIDs of publication
	KeyRotationEpoch  uint64            `cbor:"14,keyasint"` // reference cycle for active keys
	LegacyAnchor      []byte            `cbor:"15,keyasint"` // H(last v1 block) for migration (genesis only)
	Metadata          map[string][]byte `cbor:"16,keyasint"` // Extended metadata (e.g., degraded label)
	Validators        []ValidatorInfo   `cbor:"17,keyasint"` // Canonical validator set
}

// ProvenanceEntry represents an anchored provenance entry v2.0.
type ProvenanceEntry struct {
	Hash       [32]byte  `cbor:"0,keyasint"`
	Submitter  [16]byte  `cbor:"1,keyasint"`
	Timestamp  int64     `cbor:"2,keyasint"`
	Label      string    `cbor:"3,keyasint,omitempty"`
	Approver   *[16]byte `cbor:"4,keyasint,omitempty"`
	Reference  *[32]byte `cbor:"5,keyasint,omitempty"`
	Signature  []byte    `cbor:"6,keyasint,omitempty"`
	MandateRef *[32]byte `cbor:"7,keyasint,omitempty"`
}

// ValidatorInfo represents a validator in the canonical validator set.
type ValidatorInfo struct {
	ValidatorID  [16]byte   `cbor:"0,keyasint"`
	Dilithium3PK [1952]byte `cbor:"1,keyasint"`
	VRFPK        [32]byte   `cbor:"2,keyasint"`
	ContractHash [32]byte   `cbor:"3,keyasint"`
}

// MandateLabel is the provenance entry label that identifies a mandate submission.
// Mandates are ordinary provenance entries, not a block header field, so the label
// lives on the entry rather than inside the mandate body.
const MandateLabel = "3cp:mandate:v1"

// MandateEntry is a signed, versioned, time-bounded declaration of anchoring
// requirements (3CP v2.0 §13, spec/schemas/mandate.cddl).
//
// A mandate states what MUST be anchored, so that an auditor can later compare the
// chain against the obligation. The chain of versions via PrevVersion makes the
// policy history auditable, and PolicyHash references the external policy document
// the mandate was derived from.
//
// Wire keys follow mandate.cddl exactly. Earlier revisions of this struct carried a
// Label field at key 0 and omitted the identifier, signature and policy references,
// which left MandateID a stub returning zero and made compliance checks unable to
// name the mandate they verified.
type MandateEntry struct {
	ID          [32]byte `cbor:"0,keyasint"` // BLAKE3-256 of the canonical CBOR excluding Signature
	Authority   [16]byte `cbor:"1,keyasint"` // RootID that issued this mandate
	Version     uint64   `cbor:"2,keyasint"` // increments on each revision
	PrevVersion [32]byte `cbor:"3,keyasint"` // zero for the first version, else the prior mandate's ID
	ValidFrom   int64    `cbor:"4,keyasint"` // UnixNano
	ValidUntil  int64    `cbor:"5,keyasint"` // UnixNano; 0 = never expires
	Supersedes  [32]byte `cbor:"6,keyasint"` // zero if no prior mandate
	Rules       []Rule   `cbor:"7,keyasint"`
	PolicyHash  [32]byte `cbor:"8,keyasint"`            // BLAKE3-256 of the anchoring policy document
	PolicyURI   []byte   `cbor:"9,keyasint,omitempty"`  // optional pointer to the policy text
	Signature   []byte   `cbor:"10,keyasint,omitempty"` // Dilithium3 from Authority over the CBOR excluding this field
}

// MandateID computes the mandate's identifier: BLAKE3-256 over the canonical CBOR of
// the mandate with the identifier and the signature excluded.
//
// Both derived fields have to be excluded, not just the signature. The identifier
// occupies key 0, so including it would make the definition circular: assigning the
// result would change the bytes that produced it, and no mandate could ever verify.
// What remains covered is every field an auditor relies on — authority, version
// lineage, validity window, supersession, rules and policy references.
func (m *MandateEntry) MandateID() [32]byte {
	clone := *m
	clone.ID = [32]byte{}
	clone.Signature = nil
	encoded, err := deterministicMode.Marshal(&clone)
	if err != nil {
		return [32]byte{}
	}
	return blake3.Sum256(encoded)
}

// VerifyHash reports whether the stored ID commits to the mandate's contents.
func (m *MandateEntry) VerifyHash() bool {
	return m.ID == m.MandateID()
}

// IsActiveAt reports whether the mandate is in force at the given UnixNano timestamp.
// A ValidUntil of 0 means it never expires.
func (m *MandateEntry) IsActiveAt(timestamp int64) bool {
	if timestamp < m.ValidFrom {
		return false
	}
	return m.ValidUntil == 0 || timestamp <= m.ValidUntil
}

// MarshalPayloadCBOR encodes the mandate excluding Signature, which is the exact byte
// string the Authority signs and that MandateID is computed over.
func (m *MandateEntry) MarshalPayloadCBOR() ([]byte, error) {
	clone := *m
	clone.Signature = nil
	return deterministicMode.Marshal(&clone)
}

// UnmarshalMandateEntry decodes a mandate from canonical CBOR and verifies that its
// identifier commits to the decoded contents.
func UnmarshalMandateEntry(data []byte) (*MandateEntry, error) {
	var m MandateEntry
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if !m.VerifyHash() {
		return nil, ErrMandateHashMismatch
	}
	return &m, nil
}

// MarshalMandateEntry encodes a mandate to canonical CBOR.
func MarshalMandateEntry(m *MandateEntry) ([]byte, error) {
	return deterministicMode.Marshal(m)
}

// Rule represents a mandate rule: one event class and the conditions under which
// anchoring it becomes mandatory.
//
// MaxDeferralSec is what makes omission detectable: within any window of that length,
// at least one matching event must be anchored. Zero means the whole verification
// window counts as a single expectation.
type Rule struct {
	EventClass          string   `cbor:"0,keyasint"`
	Description         string   `cbor:"1,keyasint"`
	SeverityMin         float64  `cbor:"2,keyasint"`
	SeverityMax         float64  `cbor:"3,keyasint"`
	AssetCriticalityMin uint     `cbor:"4,keyasint"`
	RegulatoryScope     []string `cbor:"5,keyasint"`
	Mandatory           bool     `cbor:"6,keyasint"`
	RequiredFields      []string `cbor:"7,keyasint"`
	MaxDeferralSec      uint64   `cbor:"8,keyasint"`

	// Fields carries consensus and anchor configuration values. It is a Gleipnir
	// extension beyond the CDDL, which stops at key 8, and is what genesis populates
	// for rules such as "3cp:consensus-config".
	Fields map[string]interface{} `cbor:"9,keyasint,omitempty"`
}

// QuorumConfig defines the quorum parameters for BFT consensus.
type QuorumConfig struct {
	TotalValidators int `cbor:"0,keyasint"`
	RequiredSigs    int `cbor:"1,keyasint"`
}

// DefaultQuorumConfig returns the classic 3/3 quorum config.
func DefaultQuorumConfig() QuorumConfig {
	return QuorumConfig{
		TotalValidators: 3,
		RequiredSigs:    3,
	}
}

// IsValid checks if the quorum config is valid.
func (q QuorumConfig) IsValid() bool {
	return q.TotalValidators > 0 && q.RequiredSigs > 0 && q.RequiredSigs <= q.TotalValidators
}

// CloneBlock returns a deep copy of a block.
//
// A Block holds reference types (maps and slices), so a shallow copy shares mutable
// state with the original. That matters wherever a block crosses an ownership
// boundary — in particular the gossip bus, where one node publishes a block and
// another verifies it: with a shallow copy the publisher's later in-place edits (the
// degraded-mode label, trimming PrepareSigs) are visible to the verifier, so the block
// being verified is not the block that was proposed.
//
// Callers that store or return a block must clone it rather than copying the struct.
func CloneBlock(b *Block) *Block {
	if b == nil {
		return nil
	}
	cp := *b

	if b.PrevHash != nil {
		cp.PrevHash = append([]byte(nil), b.PrevHash...)
	}
	if b.StateRoot != nil {
		cp.StateRoot = append([]byte(nil), b.StateRoot...)
	}
	if b.BlockHash != nil {
		cp.BlockHash = append([]byte(nil), b.BlockHash...)
	}
	if b.PrepareSigsBitmap != nil {
		cp.PrepareSigsBitmap = append([]byte(nil), b.PrepareSigsBitmap...)
	}
	if b.CommitSig != nil {
		cp.CommitSig = append([]byte(nil), b.CommitSig...)
	}
	if b.LegacyAnchor != nil {
		cp.LegacyAnchor = append([]byte(nil), b.LegacyAnchor...)
	}
	if b.ExternalAnchors != nil {
		cp.ExternalAnchors = append([]string(nil), b.ExternalAnchors...)
	}

	if b.PrepareSigs != nil {
		cp.PrepareSigs = make([][]byte, len(b.PrepareSigs))
		for i, sig := range b.PrepareSigs {
			cp.PrepareSigs[i] = append([]byte(nil), sig...)
		}
	}
	if b.Anchored != nil {
		cp.Anchored = make([]ProvenanceEntry, len(b.Anchored))
		for i, e := range b.Anchored {
			cp.Anchored[i] = CloneProvenanceEntry(&e)
		}
	}
	if b.Validators != nil {
		cp.Validators = make([]ValidatorInfo, len(b.Validators))
		copy(cp.Validators, b.Validators)
	}
	if b.Metadata != nil {
		cp.Metadata = make(map[string][]byte, len(b.Metadata))
		for k, v := range b.Metadata {
			cp.Metadata[k] = append([]byte(nil), v...)
		}
	}

	return &cp
}

// CloneProvenanceEntry returns a deep copy of a provenance entry.
func CloneProvenanceEntry(e *ProvenanceEntry) ProvenanceEntry {
	if e == nil {
		return ProvenanceEntry{}
	}
	cp := *e
	if e.Approver != nil {
		a := *e.Approver
		cp.Approver = &a
	}
	if e.Reference != nil {
		r := *e.Reference
		cp.Reference = &r
	}
	if e.MandateRef != nil {
		m := *e.MandateRef
		cp.MandateRef = &m
	}
	if e.Signature != nil {
		cp.Signature = append([]byte(nil), e.Signature...)
	}
	return cp
}

// ComputeBlockHash computes the SHA-256 hash of a block per 3CP spec §4.4.
// BlockHash = SHA-256(LE64(Index) || PrevHash || StateRoot || Proposer || HashOfAnchoredEntries || LE64(Timestamp) || QuorumConfigCanonical)
func ComputeBlockHash(b *Block) []byte {
	h := sha256.New()

	// Index (LE64)
	var idxBuf [8]byte
	binary.LittleEndian.PutUint64(idxBuf[:], b.Index)
	h.Write(idxBuf[:])

	// PrevHash (32 bytes)
	h.Write(b.PrevHash)

	// StateRoot (32 bytes)
	h.Write(b.StateRoot)

	// Proposer (16 bytes)
	h.Write(b.Proposer[:])

	// HashOfAnchoredEntries: BLAKE3-256 of canonical CBOR of Anchored array (spec §4.4)
	anchoredCBOR, _ := CanonicalCBOR(b.Anchored)
	hashOfAnchored := blake3.Sum256(anchoredCBOR)
	h.Write(hashOfAnchored[:])

	// Timestamp (LE64)
	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], uint64(b.Timestamp))
	h.Write(tsBuf[:])

	// QuorumConfigCanonical: canonical CBOR of QuorumConfig
	quorumCBOR, _ := deterministicMode.Marshal(b.Quorum)
	h.Write(quorumCBOR)

	return h.Sum(nil)
}

// ComputeHash computes and returns the SHA-256 hash of the block.
func (b *Block) ComputeHash() []byte {
	return ComputeBlockHash(b)
}

// VerifyHash checks if the stored BlockHash matches the computed hash.
func (b *Block) VerifyHash() bool {
	return bytes.Equal(b.BlockHash, b.ComputeHash())
}
