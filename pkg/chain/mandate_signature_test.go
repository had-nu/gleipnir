// Mandate authority signature tests — 3CP v2.0 §15.
package chain

import (
	"bytes"
	"testing"

	"github.com/had-nu/gleipnir/pkg/identity"
)

func mandateSeed(n byte) []byte {
	s := make([]byte, identity.Dilithium3SeedSize)
	for i := range s {
		s[i] = n + byte(i)
	}
	return s
}

func testMandate(t *testing.T) *MandateEntry {
	t.Helper()
	return &MandateEntry{
		Authority:  [16]byte{1},
		Version:    1,
		ValidFrom:  1700000000000000000,
		ValidUntil: 1800000000000000000,
		Rules: []Rule{{
			EventClass:     "3cp:consensus-config",
			RequiredFields: []string{"signature", "reference"},
			Mandatory:      true,
		}},
	}
}

// TestMandateSignAndVerify is the happy path: a mandate signed by the holder of the key
// verifies.
func TestMandateSignAndVerify(t *testing.T) {
	pk, sk, err := identity.GenerateDilithiumKeyFromSeed(mandateSeed(1))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	m := testMandate(t)
	if err := m.SignWithAuthority(sk); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}
	if len(m.Signature) != MandateSignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(m.Signature), MandateSignatureSize)
	}
	if !m.VerifyHash() {
		t.Fatal("identifier does not commit to the contents after signing")
	}
	if !m.VerifyAuthoritySignature(pk[:]) {
		t.Fatal("signature did not verify against the signing key")
	}
}

// TestMandateUnsignedDoesNotVerify is the property this file exists for: a mandate with
// no signature is not authentic, and must never be treated as policy.
func TestMandateUnsignedDoesNotVerify(t *testing.T) {
	pk, _, err := identity.GenerateDilithiumKeyFromSeed(mandateSeed(1))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	m := testMandate(t)
	m.ID = m.MandateID()
	if m.VerifyAuthoritySignature(pk[:]) {
		t.Fatal("an unsigned mandate verified")
	}
}

// TestMandateWrongSignerRejected covers a mandate signed by someone other than the named
// authority: possession of a valid key is not the same as being the issuer.
func TestMandateWrongSignerRejected(t *testing.T) {
	_, attackerSK, err := identity.GenerateDilithiumKeyFromSeed(mandateSeed(9))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	authorityPK, _, err := identity.GenerateDilithiumKeyFromSeed(mandateSeed(1))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	m := testMandate(t)
	m.Authority = [16]byte{7} // claims to be a root the attacker does not control
	if err := m.SignWithAuthority(attackerSK); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}
	if m.VerifyAuthoritySignature(authorityPK[:]) {
		t.Fatal("a mandate signed by the wrong key verified against the named authority")
	}
}

// TestMandateTamperingBreaksSignature covers a mandate that was signed and then edited:
// the signature covers the canonical payload, so any change must invalidate it.
func TestMandateTamperingBreaksSignature(t *testing.T) {
	pk, sk, err := identity.GenerateDilithiumKeyFromSeed(mandateSeed(1))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	signed := testMandate(t)
	if err := signed.SignWithAuthority(sk); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}

	for name, mutate := range map[string]func(*MandateEntry){
		"relax the rules": func(m *MandateEntry) { m.Rules[0].RequiredFields = nil },
		"drop the rules":  func(m *MandateEntry) { m.Rules = nil },
		"extend validity": func(m *MandateEntry) { m.ValidUntil = 1 << 40 },
		"bump version":    func(m *MandateEntry) { m.Version = 99 },
		"change authority": func(m *MandateEntry) {
			m.Authority = [16]byte{0xAB}
		},
	} {
		t.Run(name, func(t *testing.T) {
			edited := *signed
			edited.Rules = append([]Rule(nil), signed.Rules...)
			mutate(&edited)

			if edited.VerifyAuthoritySignature(pk[:]) {
				t.Fatal("tampering left the signature valid")
			}
			// And the stored identifier must no longer commit to the contents, so the
			// body cannot be presented under its old identity either.
			if edited.VerifyHash() {
				t.Fatal("tampering left the identifier committing to the contents")
			}
		})
	}
}

// TestMandateSignatureDoesNotAffectIdentifier records why the payload excludes both the
// signature and the identifier: including either would make the definition circular.
func TestMandateSignatureDoesNotAffectIdentifier(t *testing.T) {
	_, sk, err := identity.GenerateDilithiumKeyFromSeed(mandateSeed(1))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	unsigned := testMandate(t)
	unsigned.ID = unsigned.MandateID()

	signed := testMandate(t)
	if err := signed.SignWithAuthority(sk); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}
	if signed.ID != unsigned.ID {
		t.Fatal("signing changed the identifier; the payload must exclude the signature")
	}
	if !bytes.Equal(signed.MarshalPayloadMust(t), unsigned.MarshalPayloadMust(t)) {
		t.Fatal("the signed payload differs from the unsigned payload")
	}
}

// MarshalPayloadMust is a test helper for comparing payloads.
func (m *MandateEntry) MarshalPayloadMust(t *testing.T) []byte {
	t.Helper()
	b, err := m.MarshalPayloadCBOR()
	if err != nil {
		t.Fatalf("MarshalPayloadCBOR: %v", err)
	}
	return b
}

// TestMandateSignRejectsWrongKeyLength keeps a malformed key from producing a signature
// that silently never verifies.
func TestMandateSignRejectsWrongKeyLength(t *testing.T) {
	m := testMandate(t)
	if err := m.SignWithAuthority([]byte("too short")); err == nil {
		t.Fatal("SignWithAuthority accepted a key of the wrong length")
	}
}
