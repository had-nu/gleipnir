// Mandate authority signatures — 3CP v2.0 §13.
//
// mandate.cddl gives a mandate entry a Signature at key 10, made by the Authority over
// the canonical CBOR of the entry with both the signature and the identifier excluded.
// Without that signature the Authority field is only an assertion: anyone able to
// submit could install a mandate naming any RootID as its issuer, and the rest of the
// network would treat it as authentic policy.
package chain

import (
	"errors"

	"github.com/had-nu/gleipnir/pkg/identity"
)

// ErrMandateSignature is returned when a mandate's authority signature is absent or
// does not verify.
var ErrMandateSignature = errors.New("3cp: invalid mandate authority signature")

// ErrMandateSigning is returned when a mandate cannot be signed.
var ErrMandateSigning = errors.New("3cp: mandate signing failed")

// MandateSignatureSize is the size of a mandate authority signature.
const MandateSignatureSize = identity.Dilithium3SignatureSize

// SignWithAuthority signs the mandate with the authority's ML-DSA-65 key and then
// stamps the identifier.
//
// The identifier is assigned after signing because MandateID excludes both the
// signature and the identifier; either order produces the same value, and doing it this
// way means a caller cannot end up with a signed body whose stored identifier was
// never checked.
func (m *MandateEntry) SignWithAuthority(secretKey []byte) error {
	if len(secretKey) != identity.Dilithium3SecretKeySize {
		return ErrMandateSigning
	}
	payload, err := m.MarshalPayloadCBOR()
	if err != nil {
		return err
	}
	sig := identity.SignDilithium(secretKey, payload)
	if len(sig) != MandateSignatureSize {
		return ErrMandateSigning
	}
	m.Signature = sig
	m.ID = m.MandateID()
	return nil
}

// VerifyAuthoritySignature reports whether the mandate carries a signature from the
// holder of publicKey over the canonical mandate payload.
//
// publicKey is the authority's ML-DSA-65 verifying key. Resolving the Authority field
// to a key is the caller's job: this verifies possession, not identity, and identity
// comes from the validator set rather than from the mandate itself.
func (m *MandateEntry) VerifyAuthoritySignature(publicKey []byte) bool {
	if len(m.Signature) != MandateSignatureSize {
		return false
	}
	payload, err := m.MarshalPayloadCBOR()
	if err != nil {
		return false
	}
	return identity.VerifyDilithium(publicKey, payload, m.Signature)
}
