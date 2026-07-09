// IPC cycle state.
package consensus

import "github.com/had-nu/gleipnir/pkg/chain"

type CycleState struct {
	Cycle   uint64
	Pending []chain.ProvenanceEntry
}
