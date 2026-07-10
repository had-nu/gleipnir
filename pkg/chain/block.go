// IPC block and entry types.
package chain

type Block struct {
	Index       uint64     `cbor:"0,keyasint"`
	PrevHash    []byte     `cbor:"1,keyasint"`
	StateRoot   []byte     `cbor:"2,keyasint"`
	Proposer    []byte     `cbor:"3,keyasint"`
	Triad       [3][]byte  `cbor:"4,keyasint"`
	Anchored    []ProvenanceEntry `cbor:"5,keyasint"`
	Lambda1     float64    `cbor:"6,keyasint"`
	Timestamp   int64      `cbor:"7,keyasint"`
	Sigs        [][]byte   `cbor:"8,keyasint"` // Flexible signature count
	Validators  [][]byte   `cbor:"9,keyasint"` // Validator public keys for this block
	Quorum      QuorumConfig `cbor:"10,keyasint"`
	BlockHash   []byte     `cbor:"11,keyasint"`
}

type ProvenanceEntry struct {
	Hash      [32]byte `cbor:"0,keyasint"`
	Submitter []byte   `cbor:"1,keyasint"`
	Timestamp int64    `cbor:"2,keyasint"`
	Label     string   `cbor:"3,keyasint,omitempty"`
}

// Triad represents the three signers for a block (legacy 3/3).
type Triad struct {
	A, B, C []byte    `cbor:"0,keyasint"`
	Proofs  [3][]byte `cbor:"1,keyasint"`
	Betas   [3][]byte `cbor:"2,keyasint"`
}

// QuorumConfig defines the quorum parameters for BFT consensus.
type QuorumConfig struct {
	TotalValidators int `cbor:"0,keyasint"` // Total number of validators (n)
	RequiredSigs    int `cbor:"1,keyasint"` // Minimum required signatures (m)
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