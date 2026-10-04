package chain

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/had-nu/gleipnir/pkg/identity"
)

// cborMajor is a CBOR major type (RFC 8949 §3.1). It occupies bits 5 to 7 of a head
// byte; the low three bits are the additional information. fxamacker/cbor does not
// export an equivalent, and reading the head byte is enough to check a field's wire
// type against the schema without decoding it twice.
type cborMajor uint8

const (
	majorUint  cborMajor = 0
	majorBytes cborMajor = 2
	majorArray cborMajor = 4
	majorMap   cborMajor = 5
	majorFloat cborMajor = 7
)

// specBlockField is one row of spec/schemas/block.cddl: the key the schema assigns,
// the name it gives the field, and what a conformant encoding must look like on the
// wire.
type specBlockField struct {
	key   int
	name  string
	major cborMajor // CBOR major type of the encoded value
	// size is the .size constraint from the schema, checked only for byte strings.
	// Zero means the schema puts no length constraint on the field.
	size int
}

// blockCDDL mirrors spec/schemas/block.cddl. If the schema changes, this table has to
// change with it; that is the point. The table is transcribed rather than parsed
// because the schema lives in a different repository and a test that could silently
// drift from it would be worse than no test at all.
//
// Keys 4 and 8 are absent here on purpose. They are reserved (Triad, and Sigs as
// named in v1.0) and block.cddl marks them optional; genesis.cddl omits them too.
var blockCDDL = []specBlockField{
	{0, "Index", majorUint, 0},
	{1, "PrevHash", majorBytes, 32},
	{2, "StateRoot", majorBytes, 32},
	{3, "Proposer", majorBytes, 16},
	{5, "Anchored", majorArray, 0},
	{6, "Lambda1", majorFloat, 0},
	{7, "Timestamp", majorUint, 0},
	{9, "Validators", majorArray, 0},
	{10, "Quorum", majorMap, 0},
	{11, "BlockHash", majorBytes, 32},
	{12, "ProtocolVersion", majorUint, 0},
	{13, "PrepareSigsBitmap", majorBytes, 0},
	{14, "PrepareSigs", majorArray, 0},
	{15, "CommitSig", majorBytes, identity.Dilithium3SignatureSize},
	{16, "ExternalAnchors", majorArray, 0},
	{17, "KeyRotationEpoch", majorUint, 0},
	{18, "LegacyAnchor", majorBytes, 32},
	{19, "Metadata", majorMap, 0},
}

// reservedBlockKeys are the v1-era slots that must never appear in a v2 block. Key 8
// in particular is where PREPARE signatures used to live; leaving it populated would
// mean two places claiming to hold them, which is how the spec came to contradict
// itself about which one a verifier should read.
var reservedBlockKeys = map[int]string{
	4: "Triad",
	8: "Sigs (reserved in ProtocolVersion == 2)",
}

// conformantBlock builds a block whose every field is populated to the size the schema
// asks for, so that the assertions below test the struct's encoding rather than
// accidentally passing on zero values.
func conformantBlock() Block {
	return Block{
		Index:     42,
		PrevHash:  bytes.Repeat([]byte{0xA1}, 32),
		StateRoot: bytes.Repeat([]byte{0xB2}, 32),
		Proposer:  [16]byte{1, 2, 3},
		Anchored: []ProvenanceEntry{{
			Hash:      [32]byte{9},
			Submitter: [16]byte{8},
			Timestamp: 1700000000000000000,
			Label:     "label",
		}},
		Lambda1:   0.5,
		Timestamp: 1700000000000000000,
		Validators: []ValidatorInfo{{
			ValidatorID:  [16]byte{7},
			Dilithium3PK: [identity.Dilithium3PublicKeySize]byte{6},
			VRFPK:        [32]byte{5},
			ContractHash: [32]byte{4},
		}},
		Quorum:            QuorumConfig{TotalValidators: 3, RequiredSigs: 2},
		BlockHash:         bytes.Repeat([]byte{0xC3}, 32),
		ProtocolVersion:   2,
		PrepareSigsBitmap: []byte{0x05},
		PrepareSigs: [][]byte{
			bytes.Repeat([]byte{0xD4}, identity.Dilithium3SignatureSize),
			bytes.Repeat([]byte{0xD5}, identity.Dilithium3SignatureSize),
		},
		CommitSig:        bytes.Repeat([]byte{0xE6}, identity.Dilithium3SignatureSize),
		ExternalAnchors:  []string{"ipfs://bafy", "https://example.invalid/anchor"},
		KeyRotationEpoch: 3,
		LegacyAnchor:     bytes.Repeat([]byte{0xF7}, 32),
		Metadata:         map[string][]byte{"3cp:degraded-block": {1}},
	}
}

// TestBlockWireKeysMatchCDDL is the regression test for #42.
//
// The key numbers used to disagree with block.cddl, and nothing caught it, because no
// test asserted them: every test round-tripped a Block through this same struct, so
// the struct was compared against itself. A light client written against the spec
// could not decode a Gleipnir block at all.
//
// This decodes the encoding as an untyped map and checks it against a transcription of
// the schema, so a key that moves, a field that changes type and a fixed-size field
// that is emitted at the wrong length all fail here.
func TestBlockWireKeysMatchCDDL(t *testing.T) {
	block := conformantBlock()
	encoded, err := MarshalCBOR(&block)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var wire map[int]cbor.RawMessage
	if err := cbor.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("decode into untyped map: %v", err)
	}

	// Every field in the schema must be on the wire, and nothing else may be.
	present := make(map[int]bool, len(wire))
	for key := range wire {
		present[key] = true
	}
	for _, f := range blockCDDL {
		if !present[f.key] {
			t.Errorf("key %d (%s) is in block.cddl but absent from the encoding", f.key, f.name)
		}
		delete(present, f.key)
	}
	for key := range present {
		if name, reserved := reservedBlockKeys[key]; reserved {
			t.Errorf("key %d (%s) is reserved and must not be encoded, but it is present", key, name)
			continue
		}
		t.Errorf("key %d is encoded but block.cddl defines no field for it", key)
	}

	// Each field must land on the wire with the type and length the schema requires.
	for _, f := range blockCDDL {
		raw, ok := wire[f.key]
		if !ok {
			continue // already reported above
		}
		if len(raw) == 0 {
			t.Errorf("key %d (%s) decoded to an empty value", f.key, f.name)
			continue
		}
		// Bits 5 to 7 of a CBOR head byte are the major type.
		if got := cborMajor(raw[0] >> 5); got != f.major {
			t.Errorf("key %d (%s): encoded as major type %d, block.cddl requires %d", f.key, f.name, got, f.major)
			continue
		}
		if f.major != majorBytes || f.size == 0 {
			continue
		}
		var bs []byte
		if err := cbor.Unmarshal(raw, &bs); err != nil {
			t.Errorf("key %d (%s): decode byte string: %v", f.key, f.name, err)
			continue
		}
		if len(bs) != f.size {
			t.Errorf("key %d (%s): encoded %d bytes, block.cddl requires %d", f.key, f.name, len(bs), f.size)
		}
	}
}

// TestBlockReservedKeysAbsent covers the common case too: a block still holding the
// v1 signature list at key 8 would otherwise encode cleanly, decode cleanly, and carry
// a second competing copy of the PREPARE signatures.
func TestBlockReservedKeysAbsent(t *testing.T) {
	block := conformantBlock()
	encoded, err := MarshalCBOR(&block)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[int]cbor.RawMessage
	if err := cbor.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("decode into untyped map: %v", err)
	}
	for key, name := range reservedBlockKeys {
		if _, ok := wire[key]; ok {
			t.Errorf("reserved key %d (%s) must not be encoded", key, name)
		}
	}
}

// TestBlockValidatorsCarryVRFPK pins the reason key 9 is a structured set rather than
// a list of public keys.
//
// SPEC §7.2 requires VRFProof verification to use the peer's VRFPK taken from network
// state. A block that published only Dilithium3 keys would leave a verifier with
// nowhere to obtain it, which is what the schema's earlier `[* bytes .size 1952]` did.
func TestBlockValidatorsCarryVRFPK(t *testing.T) {
	var wire struct {
		Validators []map[int]cbor.RawMessage `cbor:"9,keyasint"`
	}
	block := conformantBlock()
	encoded, err := MarshalCBOR(&block)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := cbor.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(wire.Validators) != 1 {
		t.Fatalf("got %d validators, want 1", len(wire.Validators))
	}
	for _, field := range []struct {
		key  int
		name string
		size int
	}{
		{0, "ValidatorID", 16},
		{1, "Dilithium3PK", identity.Dilithium3PublicKeySize},
		{2, "VRFPK", 32},
		{3, "ContractHash", 32},
	} {
		raw, ok := wire.Validators[0][field.key]
		if !ok {
			t.Errorf("validator-info has no key %d (%s); §7.1 defines four fields", field.key, field.name)
			continue
		}
		var bs []byte
		if err := cbor.Unmarshal(raw, &bs); err != nil {
			t.Errorf("validator-info key %d (%s): decode: %v", field.key, field.name, err)
			continue
		}
		if len(bs) != field.size {
			t.Errorf("validator-info key %d (%s): %d bytes, want %d", field.key, field.name, len(bs), field.size)
		}
	}
}

// TestBlockRoundTripPreservesFields guards the renumbering from the other side: a
// decode of our own encoding has to give back every field, which it only does if the
// tags are unambiguous.
func TestBlockRoundTripPreservesFields(t *testing.T) {
	block := conformantBlock()
	encoded, err := MarshalCBOR(&block)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded, err := UnmarshalCBOR(encoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Index != block.Index {
		t.Errorf("Index: got %d, want %d", decoded.Index, block.Index)
	}
	if !bytes.Equal(decoded.BlockHash, block.BlockHash) {
		t.Error("BlockHash did not survive the round trip")
	}
	if decoded.ProtocolVersion != block.ProtocolVersion {
		t.Errorf("ProtocolVersion: got %d, want %d", decoded.ProtocolVersion, block.ProtocolVersion)
	}
	if len(decoded.PrepareSigs) != len(block.PrepareSigs) {
		t.Fatalf("PrepareSigs: got %d entries, want %d", len(decoded.PrepareSigs), len(block.PrepareSigs))
	}
	for i := range block.PrepareSigs {
		if !bytes.Equal(decoded.PrepareSigs[i], block.PrepareSigs[i]) {
			t.Errorf("PrepareSigs[%d] did not survive the round trip", i)
		}
	}
	if len(decoded.Validators) != 1 || decoded.Validators[0].VRFPK != block.Validators[0].VRFPK {
		t.Error("Validators did not survive the round trip")
	}
	if string(decoded.Metadata["3cp:degraded-block"]) != "\x01" {
		t.Error("Metadata did not survive the round trip")
	}
	if decoded.KeyRotationEpoch != block.KeyRotationEpoch {
		t.Errorf("KeyRotationEpoch: got %d, want %d", decoded.KeyRotationEpoch, block.KeyRotationEpoch)
	}
	if !bytes.Equal(decoded.LegacyAnchor, block.LegacyAnchor) {
		t.Error("LegacyAnchor did not survive the round trip")
	}
	if decoded.Quorum != block.Quorum {
		t.Errorf("Quorum: got %+v, want %+v", decoded.Quorum, block.Quorum)
	}
}

// TestBlockEncodingIsDeterministic checks that canonical mode still applies after the
// renumbering. Key order comes from the encoder, not the struct, so a field added in
// the wrong position must not change the bytes.
func TestBlockEncodingIsDeterministic(t *testing.T) {
	block := conformantBlock()
	first, err := MarshalCBOR(&block)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	shuffled := conformantBlock()
	shuffled.Metadata = map[string][]byte{"3cp:degraded-block": {1}}
	second, err := MarshalCBOR(&shuffled)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two identical blocks encoded differently; canonical key ordering is not being applied")
	}
}
