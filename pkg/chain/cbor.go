// IPC chain — CBOR canonical serialization.
package chain

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var deterministicMode cbor.EncMode

func init() {
	var err error
	deterministicMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize CBOR canonical mode: %v", err))
	}
}

// MarshalCBOR encodes a block to canonical CBOR per 3CP spec §4.1.
func MarshalCBOR(b *Block) ([]byte, error) {
	return deterministicMode.Marshal(b)
}

// UnmarshalCBOR decodes a block from canonical CBOR.
func UnmarshalCBOR(data []byte) (*Block, error) {
	var b Block
	if err := cbor.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// MarshalProvenanceEntry encodes a provenance entry to canonical CBOR.
func MarshalProvenanceEntry(e *ProvenanceEntry) ([]byte, error) {
	return deterministicMode.Marshal(e)
}

// UnmarshalProvenanceEntry decodes a provenance entry from canonical CBOR.
func UnmarshalProvenanceEntry(data []byte) (*ProvenanceEntry, error) {
	var e ProvenanceEntry
	if err := cbor.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// CanonicalCBOR returns the canonical CBOR encoding of anchored entries for HashOfAnchoredEntries.
func CanonicalCBOR(entries []ProvenanceEntry) ([]byte, error) {
	return deterministicMode.Marshal(entries)
}