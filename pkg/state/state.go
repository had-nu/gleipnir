// IPC network state — Laplacian diffusion supervision.
package state

import (
	"encoding/hex"

	"github.com/had-nu/gleipnir/pkg/chain"
)

type NetworkState struct {
	Cycle          uint64                `cbor:"0,keyasint"`
	Nodes          map[string]NodeState  `cbor:"1,keyasint"`
	Graph          ReputationGraph       `cbor:"2,keyasint"`
	Lambda1        float64               `cbor:"3,keyasint"`
	SupervisionRoot [32]byte             `cbor:"4,keyasint"`
	ActiveMandates  []chain.MandateEntry  `cbor:"5,keyasint"`
	ValidatorSet    []ValidatorInfo       `cbor:"6,keyasint"` // canonical ordering
}

type NodeState struct {
	UID          [16]byte  `cbor:"0,keyasint"`
	Status       float64   `cbor:"1,keyasint"`
	Consecutive  uint64    `cbor:"2,keyasint"`
	JoinCycle    uint64    `cbor:"3,keyasint"`
	Dilithium3PK [1952]byte `cbor:"4,keyasint,omitempty"` // Dilithium3 public key
	VRFPK        [32]byte  `cbor:"5,keyasint,omitempty"`   // VRF public key (Ristretto255)
}

type ReputationGraph struct {
	Edges []Edge `cbor:"0,keyasint"`
}

type Edge struct {
	From   string  `cbor:"0,keyasint"`
	To     string  `cbor:"1,keyasint"`
	Weight float64 `cbor:"2,keyasint"`
}

// ValidatorInfo represents a validator in the canonical validator set.
type ValidatorInfo struct {
	ValidatorID  [16]byte  `cbor:"0,keyasint"`
	Dilithium3PK [1952]byte `cbor:"1,keyasint"`
	VRFPK        [32]byte  `cbor:"2,keyasint"`
	ContractHash [32]byte  `cbor:"3,keyasint"`
}

func (n NodeState) UIDHex() string {
	return hex.EncodeToString(n.UID[:])
}