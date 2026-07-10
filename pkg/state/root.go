// IPC state root computation (Blake3).
package state

import (
	"github.com/fxamacker/cbor/v2"
	"lukechampine.com/blake3"
)

type networkStateForRoot struct {
	Cycle    uint64               `cbor:"0,keyasint"`
	Nodes    map[string]NodeState `cbor:"1,keyasint"`
	Graph    ReputationGraph      `cbor:"2,keyasint"`
	Lambda1  float64              `cbor:"3,keyasint"`
}

func ComputeSupervisionRoot(s NetworkState) []byte {
	partial := networkStateForRoot{
		Cycle:   s.Cycle,
		Nodes:   s.Nodes,
		Graph:   s.Graph,
		Lambda1: s.Lambda1,
	}
	em, _ := cbor.CanonicalEncOptions().EncMode()
	data, err := em.Marshal(partial)
	if err != nil {
		panic(err)
	}
	sum := blake3.Sum256(data)
	return sum[:]
}
