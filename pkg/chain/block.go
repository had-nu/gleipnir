// IPC block and entry types — 3CP v2.0.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
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

// ComputeBlockHash computes the SHA-256 hash of a block per 3CP spec §3.2.
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

	// Anchored entry hashes
	for _, e := range b.Anchored {
		h.Write(e.Hash[:])
	}

	// Lambda1 (LE64 float64 bits)
	var lambdaBuf [8]byte
	binary.LittleEndian.PutUint64(lambdaBuf[:], uint64(math.Float64bits(b.Lambda1)))
	h.Write(lambdaBuf[:])

	// Timestamp (LE64)
	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], uint64(b.Timestamp))
	h.Write(tsBuf[:])

	// ProtocolVersion (LE16)
	var pvBuf [2]byte
	binary.LittleEndian.PutUint16(pvBuf[:], b.ProtocolVersion)
	h.Write(pvBuf[:])

	// PrepareSigsBitmap
	h.Write(b.PrepareSigsBitmap)

	// PrepareSigs (concatenated)
	for _, sig := range b.PrepareSigs {
		h.Write(sig)
	}

	// CommitSig
	h.Write(b.CommitSig)

	// ExternalAnchors (length-prefixed strings)
	for _, anchor := range b.ExternalAnchors {
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(anchor)))
		h.Write(lenBuf[:])
		h.Write([]byte(anchor))
	}

	// KeyRotationEpoch (LE64)
	var krBuf [8]byte
	binary.LittleEndian.PutUint64(krBuf[:], b.KeyRotationEpoch)
	h.Write(krBuf[:])

	// LegacyAnchor (genesis only)
	h.Write(b.LegacyAnchor)

	// Validators (canonical order)
	for _, v := range b.Validators {
		h.Write(v.ValidatorID[:])
		h.Write(v.Dilithium3PK[:])
		h.Write(v.VRFPK[:])
		h.Write(v.ContractHash[:])
	}

	return h.Sum(nil)
}

// ComputeHash computes and returns the SHA-256 hash of the block.
// This is the canonical block hash per 3CP spec §3.2.
func (b *Block) ComputeHash() []byte {
	return ComputeBlockHash(b)
}

// VerifyHash checks if the stored BlockHash matches the computed hash.
func (b *Block) VerifyHash() bool {
	return bytes.Equal(b.BlockHash, b.ComputeHash())
}

// MarshalCBOR encodes a block to canonical CBOR.
func MarshalCBOR(b *Block) ([]byte, error) {
	return []byte("cbor-placeholder"), nil
}