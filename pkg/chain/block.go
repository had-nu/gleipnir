// IPC block and entry types.
package chain

type Block struct {
	Index     uint64             `cbor:"0,keyasint"`
	PrevHash  []byte             `cbor:"1,keyasint"`
	StateRoot []byte             `cbor:"2,keyasint"`
	Proposer  []byte             `cbor:"3,keyasint"`
	Triad     [3][]byte          `cbor:"4,keyasint"`
	Anchored  []ProvenanceEntry  `cbor:"5,keyasint"`
	Lambda1   float64            `cbor:"6,keyasint"`
	Timestamp int64              `cbor:"7,keyasint"`
	Sigs      [3][]byte          `cbor:"8,keyasint"`
	BlockHash []byte             `cbor:"9,keyasint"`
}

type ProvenanceEntry struct {
	Hash      [32]byte `cbor:"0,keyasint"`
	Submitter []byte   `cbor:"1,keyasint"`
	Timestamp int64    `cbor:"2,keyasint"`
	Label     string   `cbor:"3,keyasint,omitempty"`
}

type Triad struct {
	A, B, C []byte    `cbor:"0,keyasint"`
	Proofs   [3][]byte `cbor:"1,keyasint"`
	Betas    [3][]byte `cbor:"2,keyasint"`
}
