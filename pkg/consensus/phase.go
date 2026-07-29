// Internal cycle phase state machine for two-phase BFT consensus.
package consensus

// CyclePhase represents the internal phase of a consensus cycle.
// This is engine-internal state, not a chain concept.
type CyclePhase int

const (
	CycleStart   CyclePhase = iota // Cycle begins, VRF election
	Preparing                      // Leader proposing, validators verifying
	Prepared                       // PREPARE quorum reached (Q signatures)
	Committing                     // Leader broadcasting B_final, validators verifying
	Committed                      // COMMIT verified, appending to chain
	CycleAborted                   // Timeout/no-quorum, entries retained
)

// String returns the phase name for logging.
func (p CyclePhase) String() string {
	switch p {
	case CycleStart:
		return "CYCLE_START"
	case Preparing:
		return "PREPARING"
	case Prepared:
		return "PREPARED"
	case Committing:
		return "COMMITTING"
	case Committed:
		return "COMMITTED"
	case CycleAborted:
		return "CYCLE_ABORTED"
	default:
		return "UNKNOWN"
	}
}

// IsTerminal returns true if the phase is a terminal state for this cycle.
func (p CyclePhase) IsTerminal() bool {
	return p == Committed || p == CycleAborted
}