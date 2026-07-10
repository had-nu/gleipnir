// IPC network state — Laplacian diffusion supervision.
package state

import "encoding/hex"

type NetworkState struct {
	Cycle    uint64               `cbor:"0,keyasint"`
	Nodes    map[string]NodeState `cbor:"1,keyasint"`
	Graph    ReputationGraph      `cbor:"2,keyasint"`
	Lambda1  float64              `cbor:"3,keyasint"`
	SupervisionRoot []byte       `cbor:"4,keyasint"`
}

type NodeState struct {
	UID        []byte  `cbor:"0,keyasint"`
	Status     float64 `cbor:"1,keyasint"`
	Consecutive uint64  `cbor:"2,keyasint"`
	JoinCycle  uint64  `cbor:"3,keyasint"`
}

type ReputationGraph struct {
	Edges []Edge `cbor:"0,keyasint"`
}

type Edge struct {
	From   string  `cbor:"0,keyasint"`
	To     string  `cbor:"1,keyasint"`
	Weight float64 `cbor:"2,keyasint"`
}

func (n NodeState) UIDHex() string {
	return hex.EncodeToString(n.UID)
}
