package consensus

import "github.com/had-nu/prana-provenance-chain/pkg/chain"

type CycleState struct {
	Cycle   uint64
	Pending []chain.ProvenanceEntry
}
