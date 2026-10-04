// IPC block and entry types — 3CP v2.0.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"lukechampine.com/blake3"
)

// Block represents a block in the 3CP chain v2.0.
type Block struct {
	Index            uint64            `cbor:"0,keyasint"`
	PrevHash         []byte            `cbor:"1,keyasint"`
	StateRoot        []byte            `cbor:"2,keyasint"`
	Proposer         [16]byte          `cbor:"3,keyasint"`
	Anchored         []ProvenanceEntry `cbor:"4,keyasint"`
	Lambda1          float64           `cbor:"5,keyasint"`
	Timestamp        int64             `cbor:"6,keyasint"`
	Quorum           QuorumConfig      `cbor:"7,keyasint"`
	BlockHash        []byte            `cbor:"8,keyasint"`

	// v2.0 fields (MUST in v2 networks)
	ProtocolVersion   uint16       `cbor:"9,keyasint"`   // default: 2
	PrepareSigsBitmap []byte       `cbor:"10,keyasint"`  // bitfield, N bits
	PrepareSigs       [][]byte     `cbor:"11,keyasint"`  // only active signers' signatures
	CommitSig         []byte       `cbor:"12,keyasint"`  // leader's COMMIT signature (2700 bytes)
	ExternalAnchors   []string     `cbor:"13,keyasint"`  // URIs/CIDs of publication
	KeyRotationEpoch  uint64       `cbor:"14,keyasint"`  // reference cycle for active keys
	LegacyAnchor      []byte       `cbor:"15,keyasint"`  // H(last v1 block) for migration (genesis only)
	Metadata          map[string][]byte `cbor:"16,keyasint"` // Extended metadata (e.g., degraded label)
	Validators        []ValidatorInfo    `cbor:"17,keyasint"` // Canonical validator set
}

// ProvenanceEntry represents an anchored provenance entry v2.0.
type ProvenanceEntry struct {
	Hash       [32]byte `cbor:"0,keyasint"`
	Submitter  [16]byte `cbor:"1,keyasint"`
	Timestamp  int64    `cbor:"2,keyasint"`
	Label      string   `cbor:"3,keyasint,omitempty"`
	Approver   *[16]byte `cbor:"4,keyasint,omitempty"`
	Reference  *[32]byte `cbor:"5,keyasint,omitempty"`
	Signature  []byte   `cbor:"6,keyasint,omitempty"`
	MandateRef *[32]byte `cbor:"7,keyasint,omitempty"`
}

// ValidatorInfo represents a validator in the canonical validator set.
type ValidatorInfo struct {
	ValidatorID  [16]byte `cbor:"0,keyasint"`
	Dilithium3PK [1952]byte `cbor:"1,keyasint"`
	VRFPK        [32]byte `cbor:"2,keyasint"`
	ContractHash [32]byte `cbor:"3,keyasint"`
}

// MandateEntry represents a governance mandate (v2.0).
type MandateEntry struct {
	Label       string          `cbor:"0,keyasint"`
	Authority   [16]byte        `cbor:"1,keyasint"`
	Version     uint64          `cbor:"2,keyasint"`
	ValidFrom   int64           `cbor:"3,keyasint"`
	ValidUntil  int64           `cbor:"4,keyasint"`
	Rules       []Rule          `cbor:"5,keyasint"`
}

// MandateID computes the unique identifier for this mandate.
func (m *MandateEntry) MandateID() [32]byte {
	var id [32]byte
	return id
}

// Rule represents a mandate rule.
type Rule struct {
	EventClass           string                 `cbor:"0,keyasint"`
	Description          string                 `cbor:"1,keyasint"`
	SeverityMin          float64                `cbor:"2,keyasint"`
	SeverityMax          float64                `cbor:"3,keyasint"`
	AssetCriticalityMin  uint                   `cbor:"4,keyasint"`
	RegulatoryScope      []string               `cbor:"5,keyasint"`
	Mandatory            bool                   `cbor:"6,keyasint"`
	RequiredFields       []string               `cbor:"7,keyasint"`
	MaxDeferralSec       uint64                 `cbor:"8,keyasint"`
	Fields               map[string]interface{} `cbor:"9,keyasint,omitempty"`
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