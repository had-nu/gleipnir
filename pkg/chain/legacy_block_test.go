package chain

import (
	"bytes"
	"testing"

	"github.com/had-nu/gleipnir/pkg/identity"
)

// legacyBlock is the pre-#42 block encoding: the same fields, the old key numbers.
// It exists so that a block written by a build from before the renumbering can be
// decoded here, and so the test below can assert what happens.
type legacyBlock struct {
	Index             uint64            `cbor:"0,keyasint"`
	PrevHash          []byte            `cbor:"1,keyasint"`
	StateRoot         []byte            `cbor:"2,keyasint"`
	Proposer          [16]byte          `cbor:"3,keyasint"`
	Anchored          []ProvenanceEntry `cbor:"4,keyasint"`
	Lambda1           float64           `cbor:"5,keyasint"`
	Timestamp         int64             `cbor:"6,keyasint"`
	Quorum            QuorumConfig      `cbor:"7,keyasint"`
	BlockHash         []byte            `cbor:"8,keyasint"`
	ProtocolVersion   uint16            `cbor:"9,keyasint"`
	PrepareSigsBitmap []byte            `cbor:"10,keyasint"`
	PrepareSigs       [][]byte          `cbor:"11,keyasint"`
	CommitSig         []byte            `cbor:"12,keyasint"`
	ExternalAnchors   []string          `cbor:"13,keyasint"`
	KeyRotationEpoch  uint64            `cbor:"14,keyasint"`
	LegacyAnchor      []byte            `cbor:"15,keyasint"`
	Metadata          map[string][]byte `cbor:"16,keyasint"`
	Validators        []ValidatorInfo   `cbor:"17,keyasint"`
}

// TestPreRenumberingBlockIsRejected pins the failure mode of the v2 chain reset.
//
// Renumbering the block's keys was only safe because a block written by an older build
// cannot be read back as a v2 block. If it could, the mismatch would be silent rather
// than loud: a decoder that tolerates the difference would take the old key 5 (a
// float, Lambda1) for the new key 5 (an array, Anchored), and from there almost every
// field would be plausible and wrong. A consensus bug of that shape surfaces as a
// chain that verifies and should not.
//
// The rejection is deterministic rather than incidental. Lambda1 is declared without
// omitempty and is always a CBOR float, while key 5 is now an array, so every
// pre-renumbering block fails at that key whatever its contents.
func TestPreRenumberingBlockIsRejected(t *testing.T) {
	legacy := legacyBlock{
		Index:             7,
		PrevHash:          bytes.Repeat([]byte{0xA1}, 32),
		StateRoot:         bytes.Repeat([]byte{0xB2}, 32),
		Anchored:          []ProvenanceEntry{{Hash: [32]byte{9}, Timestamp: 1700000000000000000}},
		Lambda1:           0.5,
		Timestamp:         1700000000000000000,
		Quorum:            QuorumConfig{TotalValidators: 3, RequiredSigs: 2},
		BlockHash:         bytes.Repeat([]byte{0xC3}, 32),
		ProtocolVersion:   2,
		PrepareSigsBitmap: []byte{0x05},
		PrepareSigs: [][]byte{
			bytes.Repeat([]byte{0xD4}, identity.Dilithium3SignatureSize),
		},
		CommitSig:        bytes.Repeat([]byte{0xE6}, identity.Dilithium3SignatureSize),
		ExternalAnchors:  []string{"ipfs://bafy"},
		KeyRotationEpoch: 3,
		LegacyAnchor:     bytes.Repeat([]byte{0xF7}, 32),
		Metadata:         map[string][]byte{"3cp:degraded-block": {1}},
		Validators: []ValidatorInfo{{
			ValidatorID:  [16]byte{7},
			Dilithium3PK: [identity.Dilithium3PublicKeySize]byte{6},
			VRFPK:        [32]byte{5},
			ContractHash: [32]byte{4},
		}},
	}

	encoded, err := deterministicMode.Marshal(&legacy)
	if err != nil {
		t.Fatalf("marshal legacy block: %v", err)
	}

	decoded, err := UnmarshalCBOR(encoded)
	if err == nil {
		t.Fatalf("a pre-renumbering block decoded as a v2 block: "+
			"Index=%d Timestamp=%d Lambda1=%v Quorum=%+v Validators=%d; "+
			"every field past the first mismatch is silently wrong",
			decoded.Index, decoded.Timestamp, decoded.Lambda1, decoded.Quorum, len(decoded.Validators))
	}
}

// TestRenumberingChangesTheEncoding guards the other direction: the same logical block
// written under the old numbering must not produce the same bytes, or the reset could
// accept a chain that was never actually renumbered.
func TestRenumberingChangesTheEncoding(t *testing.T) {
	block := conformantBlock()

	encoded, err := MarshalCBOR(&block)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Same logical block, written with the old field numbering.
	legacy := legacyBlock{
		Index:             block.Index,
		PrevHash:          block.PrevHash,
		StateRoot:         block.StateRoot,
		Proposer:          block.Proposer,
		Anchored:          block.Anchored,
		Lambda1:           block.Lambda1,
		Timestamp:         block.Timestamp,
		Quorum:            block.Quorum,
		BlockHash:         block.BlockHash,
		ProtocolVersion:   block.ProtocolVersion,
		PrepareSigsBitmap: block.PrepareSigsBitmap,
		PrepareSigs:       block.PrepareSigs,
		CommitSig:         block.CommitSig,
		ExternalAnchors:   block.ExternalAnchors,
		KeyRotationEpoch:  block.KeyRotationEpoch,
		LegacyAnchor:      block.LegacyAnchor,
		Metadata:          block.Metadata,
		Validators:        block.Validators,
	}
	legacyEncoded, err := deterministicMode.Marshal(&legacy)
	if err != nil {
		t.Fatalf("marshal legacy block: %v", err)
	}

	if bytes.Equal(encoded, legacyEncoded) {
		t.Fatal("the two encodings are identical; the renumbering changed nothing on the wire")
	}
}
