package lightclient

import (
	"github.com/had-nu/gleipnir/pkg/state"
)

// rotationConfig returns the key rotation parameters a verifier applies.
//
// Only the two fields that decide which key is authoritative in a cycle are read:
// KeyRotationLeadTime and MinKeyOverlap. A light client verifies the chain it is given
// rather than authoring new rotations, so lead time is not something it needs to enforce
// -- it validates the rotations it is handed, and NewKeyRotationValidator's rule 3
// compares EffectiveCycle against currentCycle, which the caller sets to the anchor's
// index. MinKeyOverlap does matter, because it is what bounds the overlap window whose
// length decides how long both keys verify.
func rotationConfig() state.Config {
	cfg := state.DefaultConfig
	if cfg.MinKeyOverlap == 0 {
		// A zero overlap would make a rotation's two keys authoritative for exactly one
		// cycle. state.DefaultConfig sets this; the guard is here so a future change to
		// that default cannot silently disable rotation awareness for observers.
		cfg.MinKeyOverlap = 1
	}
	return cfg
}
