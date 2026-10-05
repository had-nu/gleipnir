// Mandate authority validation — 3CP v2.0 §13.
//
// A mandate is only worth enforcing if the RootID it names as its Authority actually
// issued it. mandate.cddl carries a signature for exactly that reason, but nothing
// verified it: the Authority field was an assertion, so any submitter could install a
// mandate under another node's name and the network would treat it as authentic
// policy.
//
// This is the first of the two enforcement halves the spec describes. It proves
// provenance at admission time. It cannot detect events that were never submitted, which
// is what ComplianceChecker is for.
package validation

import (
	"fmt"

	"github.com/had-nu/gleipnir/pkg/chain"
)

// KeyLookup resolves a RootID to its ML-DSA-65 verifying key.
//
// It returns false for an unknown RootID. The resolver deliberately does not fall back
// to "no key means allow": an unverifiable issuer is exactly the case this check exists
// to reject.
type KeyLookup func(rootID [16]byte) ([]byte, bool)

// ValidateMandateAuthority verifies that a mandate body is authentic and self-consistent
// before it is allowed to influence enforcement.
//
// Four things are checked, in order of how cheaply they rule the body out:
//
//  1. The identifier commits to the contents. Without this a mandate could be presented
//     under one identity and enforced as another.
//  2. An authority signature is present and the right length.
//  3. The Authority resolves to a known key. A mandate signed by a node nobody has
//     registered is not attributable.
//  4. The signature verifies against that key over the canonical payload.
//
// The timestamp is not checked here. Whether a mandate is in force at a given moment is
// IsActiveAt's job, and rejecting an expired mandate at admission would stop an auditor
// from asking about a window it covered in the past.
func ValidateMandateAuthority(mandate *chain.MandateEntry, lookup KeyLookup) error {
	if mandate == nil {
		return ErrInvalidMandateEntry
	}
	if lookup == nil {
		return fmt.Errorf("%w: no key lookup supplied", ErrInvalidMandateEntry)
	}

	// The identifier is recomputed rather than trusted, so a body cannot carry rules
	// that differ from the identity it is presented under.
	if !mandate.VerifyHash() {
		return fmt.Errorf("%w: identifier does not commit to the mandate contents", chain.ErrMandateHashMismatch)
	}

	if len(mandate.Signature) != chain.MandateSignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d",
			chain.ErrMandateSignature, len(mandate.Signature), chain.MandateSignatureSize)
	}

	publicKey, ok := lookup(mandate.Authority)
	if !ok {
		return fmt.Errorf("%w: no registered key for authority %x",
			ErrMandateAuthorityMismatch, mandate.Authority)
	}

	if !mandate.VerifyAuthoritySignature(publicKey) {
		return fmt.Errorf("%w: authority %x did not sign this mandate",
			chain.ErrMandateSignature, mandate.Authority)
	}
	return nil
}
