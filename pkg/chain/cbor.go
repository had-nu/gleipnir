// IPC chain — CBOR canonical serialization.
package chain

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrReservedFieldPresent reports a v2 block carrying CBOR key 8, which §5.3 reserves.
//
// Defined here rather than in pkg/validation because validation imports chain, so the
// dependency cannot run the other way. pkg/validation re-exports it as
// validation.ErrReservedFieldPresent, which is where a caller finds it alongside the
// other v2 sentinels.
var ErrReservedFieldPresent = errors.New("3cp: reserved CBOR key present in a v2 block")

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
	if err := rejectReservedKeys(data); err != nil {
		return nil, err
	}
	var b Block
	if err := cbor.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// rejectReservedKeys enforces §5.3: a block with ProtocolVersion == 2 that carries
// key 8 must be rejected with ErrReservedFieldPresent.
//
// Key 8 is `Sigs`, the PREPARE-signature field in v1.0. In v2 that meaning lives in
// PrepareSigsBitmap (13) and PrepareSigsPayload (14), and key 8 is reserved. §5.3 closes
// by stating that "key 8 never has two meanings within the same network" — a guarantee
// that holds only if every implementation refuses the field rather than ignoring it.
//
// This check existed because `Block` has no field for key 8. The CBOR library therefore
// dropped it silently: Gleipnir never emitted it, so the decoder never had to look, and a
// block from a v1 emitter decoded here as a perfectly ordinary v2 block with its signature
// field missing. Emitting and rejecting are separate requirements, and only the first was
// met.
//
// Scoped to key 8 rather than to all unknown keys: §5.3 reserves this one field, and
// rejecting every unknown key would refuse extensions the spec has not discussed. The
// ProtocolVersion == 1 case is left to `spec/3CP.md` semantics, which §5.3 scopes to a
// legacy network and §17 makes a hard fork rather than a wire-compatibility question.
func rejectReservedKeys(data []byte) error {
	var raw map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(data, &raw); err != nil {
		// Not a map, or not decodable as one. cbor.Unmarshal into Block below produces
		// the real diagnostic; this is not the place to report a second opinion.
		return nil
	}

	v, hasVersion := raw[12]
	if !hasVersion {
		return nil // ProtocolVersion absent; treated as v1 by the struct decode.
	}
	var version uint16
	if err := cbor.Unmarshal(v, &version); err != nil {
		return nil // Malformed; the struct decode reports it.
	}
	if version != 2 {
		return nil // §5.3 scopes the reservation to ProtocolVersion == 2.
	}

	sigs, present := raw[8]
	if !present {
		return nil
	}
	// "present and non-null": a v1-era block that encoded key 8 as null carries no
	// signature field, so there is nothing to confuse a v2 reader with.
	if isCBORNull(sigs) {
		return nil
	}
	return fmt.Errorf("%w: key 8 (Sigs, reserved in ProtocolVersion 2)", ErrReservedFieldPresent)
}

// isCBORNull reports whether a raw CBOR item is the null simple value (0xf6).
func isCBORNull(raw cbor.RawMessage) bool {
	return len(raw) == 1 && raw[0] == 0xf6
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