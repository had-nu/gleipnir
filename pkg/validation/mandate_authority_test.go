// Mandate authority validation tests — 3CP v2.0 §15.
package validation

import (
	"errors"
	"testing"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func authoritySeed(n byte) []byte {
	s := make([]byte, identity.Dilithium3SeedSize)
	for i := range s {
		s[i] = n + byte(i)
	}
	return s
}

// authorityFixture is a signed mandate plus the key lookup that resolves its authority.
type authorityFixture struct {
	mandate   *chain.MandateEntry
	authority [identity.Dilithium3PublicKeySize]byte
	lookup    KeyLookup
}

func newAuthorityFixture(t *testing.T, seed byte) *authorityFixture {
	t.Helper()

	pk, sk, err := identity.GenerateDilithiumKeyFromSeed(authoritySeed(seed))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	mandate := &chain.MandateEntry{
		Authority:  [16]byte{seed},
		Version:    1,
		ValidFrom:  1700000000000000000,
		ValidUntil: 1800000000000000000,
		Rules: []chain.Rule{{
			EventClass:     "3cp:consensus-config",
			RequiredFields: []string{"signature"},
			Mandatory:      true,
		}},
	}
	if err := mandate.SignWithAuthority(sk); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}

	f := &authorityFixture{mandate: mandate, authority: pk}
	f.lookup = func(rootID [16]byte) ([]byte, bool) {
		if rootID != mandate.Authority {
			return nil, false
		}
		return f.authority[:], true
	}
	return f
}

// TestValidateMandateAuthorityAccepts is the happy path.
func TestValidateMandateAuthorityAccepts(t *testing.T) {
	f := newAuthorityFixture(t, 1)
	if err := ValidateMandateAuthority(f.mandate, f.lookup); err != nil {
		t.Fatalf("a properly signed mandate was rejected: %v", err)
	}
}

// TestValidateMandateAuthorityRejectsUnsigned is the case that motivated this file.
//
// mandate.cddl has always carried a signature at key 10, but nothing verified it, so
// the Authority field was an assertion. An unsigned mandate naming someone else's RootID
// would otherwise install itself as enforceable policy.
func TestValidateMandateAuthorityRejectsUnsigned(t *testing.T) {
	f := newAuthorityFixture(t, 1)
	f.mandate.Signature = nil
	f.mandate.ID = f.mandate.MandateID()

	err := ValidateMandateAuthority(f.mandate, f.lookup)
	if err == nil {
		t.Fatal("an unsigned mandate was accepted as authentic policy")
	}
	if !errors.Is(err, chain.ErrMandateSignature) {
		t.Errorf("got %v, want it to wrap chain.ErrMandateSignature", err)
	}
}

// TestValidateMandateAuthorityRejectsWrongSigner covers a mandate correctly signed by a
// key that is not the named authority's.
func TestValidateMandateAuthorityRejectsWrongSigner(t *testing.T) {
	f := newAuthorityFixture(t, 1)

	_, attackerSK, err := identity.GenerateDilithiumKeyFromSeed(authoritySeed(200))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	forged := *f.mandate
	forged.Rules = append([]chain.Rule(nil), f.mandate.Rules...)
	if err := forged.SignWithAuthority(attackerSK); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}

	if err := ValidateMandateAuthority(&forged, f.lookup); err == nil {
		t.Fatal("a mandate signed by a key other than the named authority was accepted")
	}
}

// TestValidateMandateAuthorityRejectsUnknownAuthority covers a genuinely signed mandate
// from a node this chain has no key for. Accepting it would mean enforcing policy from an
// issuer nobody can attribute.
func TestValidateMandateAuthorityRejectsUnknownAuthority(t *testing.T) {
	f := newAuthorityFixture(t, 1)

	emptyLookup := func([16]byte) ([]byte, bool) { return nil, false }
	err := ValidateMandateAuthority(f.mandate, emptyLookup)
	if err == nil {
		t.Fatal("a mandate from an unregistered authority was accepted")
	}
	if !errors.Is(err, ErrMandateAuthorityMismatch) {
		t.Errorf("got %v, want it to wrap ErrMandateAuthorityMismatch", err)
	}
}

// TestValidateMandateAuthorityRejectsTamperedRules covers a mandate whose rules were
// loosened after signing. The signature check alone would catch it; the identifier check
// matters too, because it is what stops the body being presented under a false identity.
func TestValidateMandateAuthorityRejectsTamperedRules(t *testing.T) {
	f := newAuthorityFixture(t, 1)

	tampered := *f.mandate
	tampered.Rules = []chain.Rule{{EventClass: "3cp:anything", Mandatory: false}}
	// Keep the old identifier and signature, as an attacker would.

	err := ValidateMandateAuthority(&tampered, f.lookup)
	if err == nil {
		t.Fatal("a mandate with relaxed rules kept its old identifier and signature, and was accepted")
	}
	if !errors.Is(err, chain.ErrMandateHashMismatch) {
		t.Errorf("got %v, want it to wrap chain.ErrMandateHashMismatch", err)
	}
}

// TestValidateMandateAuthorityRejectsTruncatedSignature rejects a signature of the wrong
// length before any expensive verification is attempted.
func TestValidateMandateAuthorityRejectsTruncatedSignature(t *testing.T) {
	f := newAuthorityFixture(t, 1)
	f.mandate.Signature = f.mandate.Signature[:len(f.mandate.Signature)-1]

	if err := ValidateMandateAuthority(f.mandate, f.lookup); err == nil {
		t.Fatal("a truncated signature was accepted")
	}
}

// TestValidateMandateAuthorityRequiresLookup fails closed when no key source is
// available. Defaulting to "allow" here would make the check optional by omission.
func TestValidateMandateAuthorityRequiresLookup(t *testing.T) {
	f := newAuthorityFixture(t, 1)

	if err := ValidateMandateAuthority(f.mandate, nil); err == nil {
		t.Fatal("validation passed with no key lookup supplied")
	}
	if err := ValidateMandateAuthority(nil, f.lookup); err == nil {
		t.Fatal("validation passed a nil mandate")
	}
}

// TestValidateMandateAuthorityAcceptsExpiredButSigned checks that validity is not
// enforced here.
//
// An auditor asking about a window a mandate covered in the past must be able to load
// it; refusing at admission would erase the very record the audit needs.
func TestValidateMandateAuthorityAcceptsExpiredButSigned(t *testing.T) {
	f := newAuthorityFixture(t, 1)
	f.mandate.ValidFrom = 1
	f.mandate.ValidUntil = 2
	// Re-sign so the identifier and signature commit to the expired window.
	_, sk, err := identity.GenerateDilithiumKeyFromSeed(authoritySeed(1))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := f.mandate.SignWithAuthority(sk); err != nil {
		t.Fatalf("re-sign: %v", err)
	}

	if err := ValidateMandateAuthority(f.mandate, f.lookup); err != nil {
		t.Fatalf("an expired but authentic mandate was rejected: %v", err)
	}
	if f.mandate.IsActiveAt(1700000000000000000) {
		t.Fatal("IsActiveAt reported a long-expired mandate as active")
	}
}
