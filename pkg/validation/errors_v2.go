// v2-specific error codes for 3CP protocol.
package validation

import "errors"

// v2.0 Consensus Errors
var (
	// ErrQuorumNotMet is returned when PREPARE quorum is not reached.
	ErrQuorumNotMet = errors.New("3cp: PREPARE quorum not met")

	// ErrCycleTimeout is returned when a cycle exceeds CycleTimeout.
	ErrCycleTimeout = errors.New("3cp: cycle timeout exceeded")

	// ErrDegradedMode is returned when network enters degraded mode (N < MinValidators).
	ErrDegradedMode = errors.New("3cp: network in degraded mode")

	// ErrByzantineLeader is returned when double proposal is detected.
	ErrByzantineLeader = errors.New("3cp: byzantine leader double proposal")

	// ErrInvalidPrepareSig is returned when a PREPARE signature fails verification.
	ErrInvalidPrepareSig = errors.New("3cp: invalid PREPARE signature")

	// ErrInvalidVRFProof is returned when a VRF proof fails verification.
	ErrInvalidVRFProof = errors.New("3cp: invalid VRF proof")

	// ErrSlashingEvidence is returned when slashing evidence is submitted.
	ErrSlashingEvidence = errors.New("3cp: slashing evidence detected")

	// ErrNetworkFragmented is returned when lambda1 < MinLambda1.
	ErrNetworkFragmented = errors.New("3cp: network fragmented (lambda1 below threshold)")
)

// v2.0 Key Rotation Errors
var (
	// ErrKeyRotationInvalidOldSig is returned when SignatureOld fails verification.
	ErrKeyRotationInvalidOldSig = errors.New("3cp: key rotation invalid old signature")

	// ErrKeyRotationInvalidNewSig is returned when SignatureNew fails verification.
	ErrKeyRotationInvalidNewSig = errors.New("3cp: key rotation invalid new signature")

	// ErrKeyRotationLeadTime is returned when EffectiveCycle < current + LeadTime.
	ErrKeyRotationLeadTime = errors.New("3cp: key rotation insufficient lead time")

	// ErrKeyRotationOverlap is returned when ExpiryCycle < EffectiveCycle + MinKeyOverlap.
	ErrKeyRotationOverlap = errors.New("3cp: key rotation insufficient key overlap")

	// ErrKeyRotationDuplicate is returned when a key rotation for the same validator/cycle already exists.
	ErrKeyRotationDuplicate = errors.New("3cp: key rotation already exists for cycle")
)

// v2.0 Mandate Errors
var (
	// ErrMandateInactive is returned when a mandate is not yet active.
	ErrMandateInactive = errors.New("3cp: mandate not yet active")

	// ErrMandateExpired is returned when a mandate has expired.
	ErrMandateExpired = errors.New("3cp: mandate expired")

	// ErrMandateSuperseded is returned when a mandate has been superseded.
	ErrMandateSuperseded = errors.New("3cp: mandate superseded")

	// ErrMandateAuthorityMismatch is returned when mandate authority doesn't match submitter.
	ErrMandateAuthorityMismatch = errors.New("3cp: mandate authority mismatch")

	// ErrMandateVersionConflict is returned when PrevVersion doesn't match latest.
	ErrMandateVersionConflict = errors.New("3cp: mandate version conflict")

	// ErrMandateMissingRequiredField is returned when a required field is missing per mandate rule.
	ErrMandateMissingRequiredField = errors.New("3cp: mandate required field missing")

	// ErrMandateRefRequired is returned when entry matches mandatory rule but has no MandateRef.
	ErrMandateRefRequired = errors.New("3cp: mandate reference required")
)

// v2.0 Network/Cycle Errors
var (
	// ErrPendingExpired is returned when an entry exceeds MaxPendingTTL.
	ErrPendingExpired = errors.New("3cp: pending entry expired (MaxPendingTTL exceeded)")

	// ErrMaxCycleDurationExceeded is returned when adaptive cycle would exceed MaxCycleDuration.
	ErrMaxCycleDurationExceeded = errors.New("3cp: max cycle duration exceeded")

	// ErrInvalidCycleDuration is returned when cycle duration calculation fails.
	ErrInvalidCycleDuration = errors.New("3cp: invalid cycle duration")

	// ErrSkipEmptyCyclesDisabled is returned when no entries but SkipEmptyCycles=false.
	ErrSkipEmptyCyclesDisabled = errors.New("3cp: empty cycle not allowed (SkipEmptyCycles=false)")
)

// v2.0 Anchor/Publisher Errors
var (
	// ErrPublisherNonCompliant is returned when a declared publisher fails to publish.
	ErrPublisherNonCompliant = errors.New("3cp: anchor publisher non-compliant")

	// ErrInsufficientRedundancy is returned when ExternalAnchors < MinRedundancy.
	ErrInsufficientRedundancy = errors.New("3cp: insufficient anchor redundancy")

	// ErrInvalidPublisherConfig is returned when publisher configuration is invalid.
	ErrInvalidPublisherConfig = errors.New("3cp: invalid publisher configuration")

	// ErrIPFSPublishFailed is returned when IPFS publishing fails.
	ErrIPFSPublishFailed = errors.New("3cp: IPFS publish failed")

	// ErrS3PublishFailed is returned when S3 publishing fails.
	ErrS3PublishFailed = errors.New("3cp: S3 publish failed")

	// ErrCIDMismatch is returned when published CID doesn't match content hash.
	ErrCIDMismatch = errors.New("3cp: CID mismatch with content hash")
)

// v2.0 UID0/Identity Errors
var (
	// ErrEntropyInsufficient is returned when entropy source has < 80 bits estimated entropy.
	ErrEntropyInsufficient = errors.New("3cp: entropy source insufficient (< 80 bits)")

	// ErrInvalidNetworkID is returned when NetworkID is invalid or missing.
	ErrInvalidNetworkID = errors.New("3cp: invalid network ID")

	// ErrUID0DerivationFailed is returned when HKDF derivation fails.
	ErrUID0DerivationFailed = errors.New("3cp: UID0 v2 derivation failed")
)

// v2.0 Configuration Errors
var (
	// ErrConfigInvalid is returned when configuration is invalid.
	ErrConfigInvalid = errors.New("3cp: invalid configuration")

	// ErrBatchVerifyWorkersTooLow is returned when BatchVerifyWorkers < 4.
	ErrBatchVerifyWorkersTooLow = errors.New("3cp: batch verify workers must be >= 4")

	// ErrRequiredSigsMismatch is returned when RequiredSigs != ceil(2N/3).
	ErrRequiredSigsMismatch = errors.New("3cp: RequiredSigs must equal ceil(2N/3)")

	// ErrMinValidatorsNotMet is returned when initial validators < MinValidators.
	ErrMinValidatorsNotMet = errors.New("3cp: initial validators less than MinValidators")
)

// IsV2Error checks if an error is a v2.0-specific error.
func IsV2Error(err error) bool {
	switch err {
	case ErrQuorumNotMet, ErrCycleTimeout, ErrDegradedMode, ErrByzantineLeader,
		ErrInvalidPrepareSig, ErrInvalidVRFProof, ErrSlashingEvidence, ErrNetworkFragmented,
		ErrKeyRotationInvalidOldSig, ErrKeyRotationInvalidNewSig, ErrKeyRotationLeadTime,
		ErrKeyRotationOverlap, ErrKeyRotationDuplicate,
		ErrMandateInactive, ErrMandateExpired, ErrMandateSuperseded, ErrMandateAuthorityMismatch,
		ErrMandateVersionConflict, ErrMandateMissingRequiredField, ErrMandateRefRequired,
		ErrPendingExpired, ErrMaxCycleDurationExceeded, ErrInvalidCycleDuration,
		ErrSkipEmptyCyclesDisabled,
		ErrPublisherNonCompliant, ErrInsufficientRedundancy, ErrInvalidPublisherConfig,
		ErrIPFSPublishFailed, ErrS3PublishFailed, ErrCIDMismatch,
		ErrEntropyInsufficient, ErrInvalidNetworkID, ErrUID0DerivationFailed,
		ErrConfigInvalid, ErrBatchVerifyWorkersTooLow, ErrRequiredSigsMismatch, ErrMinValidatorsNotMet:
		return true
	}
	return false
}