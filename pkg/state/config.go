// IPC diffusion configuration.
package state

import "time"

type Config struct {
	Eta                float64
	DecayRate          float64
	MinLambda1         float64
	LambdaInterval     uint64 // recompute λ₁ every N cycles; 0 = every cycle
	SMTDepth           int    // Sparse Merkle Tree depth (0 = default 256)

	// v2.0 config
	CycleTimeout        time.Duration // Max time for PREPARE phase
	MaxCycleDuration    time.Duration // Hard cap on cycle duration
	BaseInterval        time.Duration // Base cycle interval
	SafetyFactor        float64       // EWMA(RTT) * SafetyFactor
	SkipEmptyCycles     bool          // Skip cycle if no entries
	MaxPendingTTL       uint64        // Max cycles for pending entries
	BatchVerifyWorkers  int           // Workers for batch verification (0 = auto)
	KeyRotationLeadTime uint64        // Lead time for key rotation
	MinKeyOverlap       uint64        // Minimum key overlap cycles
	MinValidators       uint64        // Min validators for normal mode
	GraceCycles         uint64        // Cycles to exit degraded mode
}

var DefaultConfig = Config{
	Eta:                  0.28,
	DecayRate:            0.05,
	MinLambda1:           0.10,
	LambdaInterval:       10,
	SMTDepth:             256,
	CycleTimeout:         10 * time.Second,
	MaxCycleDuration:     10 * time.Second,
	BaseInterval:         3 * time.Second,
	SafetyFactor:         1.5,
	SkipEmptyCycles:      true,
	MaxPendingTTL:        100,
	BatchVerifyWorkers:   0, // auto
	KeyRotationLeadTime:  10,
	MinKeyOverlap:        10,
	MinValidators:        4,
	GraceCycles:          10,
}
