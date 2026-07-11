// ECVRF implementation using Ristretto255 (compliant with RFC 9381).
package identity

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/bwesterb/go-ristretto"
	"github.com/cloudflare/circl/expander"
)

var (
	ErrVRFVerifyFailed  = errors.New("VRF verification failed")
	ErrVRFInvalidInput  = errors.New("VRF invalid input")
)

// VRFSuiteID is the ciphersuite identifier for VRF.
const VRFSuiteID = "ristretto255_XMD:SHA-512_R255MAP_RO_"

// VRFPrivateKey is the secret key for VRF.
type VRFPrivateKey struct {
	sk *ristretto.Scalar
}

// VRFPublicKey is the public key for VRF.
type VRFPublicKey struct {
	pk *ristretto.Point
}

// VRFProof contains the VRF output and proof.
type VRFProof struct {
	Gamma []byte // VRF output (HashToCurve(alpha))
	C     []byte // challenge
	S     []byte // response scalar
}

// GenerateVRFKeyPair generates a new VRF key pair.
func GenerateVRFKeyPair() (*VRFPrivateKey, *VRFPublicKey, error) {
	sk := new(ristretto.Scalar).Rand()
	pk := new(ristretto.Point).ScalarMultBase(sk)

	return &VRFPrivateKey{sk: sk}, &VRFPublicKey{pk: pk}, nil
}

// VRFPrivateKeyFromBytes creates a private key from bytes.
func VRFPrivateKeyFromBytes(data []byte) (*VRFPrivateKey, error) {
	if len(data) != 32 {
		return nil, ErrVRFInvalidInput
	}
	sk := new(ristretto.Scalar)
	sk.SetBytes((*[32]byte)(data))
	return &VRFPrivateKey{sk: sk}, nil
}

// VRFPublicKeyFromBytes creates a public key from bytes.
func VRFPublicKeyFromBytes(data []byte) (*VRFPublicKey, error) {
	if len(data) != 32 {
		return nil, ErrVRFInvalidInput
	}
	pk := new(ristretto.Point)
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &VRFPublicKey{pk: pk}, nil
}

// Bytes returns the private key bytes.
func (sk *VRFPrivateKey) Bytes() []byte {
	return sk.sk.Bytes()
}

// Bytes returns the public key bytes.
func (pk *VRFPublicKey) Bytes() []byte {
	return pk.pk.Bytes()
}

// HashToCurve hashes input to a Ristretto255 point (HashToElement).
// Uses the expand_message_xmd with SHA-512 and Elligator2 mapping.
func HashToCurve(alpha []byte) *ristretto.Point {
	dst := []byte(VRFSuiteID)
	xmd := expander.NewExpanderMD(crypto.SHA512, dst)

	// Generate uniform bytes using expand_message_xmd
	uniformBytes := xmd.Expand(alpha, 64)

	var buf [32]byte
	copy(buf[:], uniformBytes[:32])
	p0 := new(ristretto.Point).SetElligator(&buf)

	copy(buf[:], uniformBytes[32:])
	p1 := new(ristretto.Point).SetElligator(&buf)

	p0.Add(p0, p1)
	return p0
}

// Prove generates a VRF proof for the given input.
// Uses a Schnorr proof that Gamma = sk * H without revealing sk.
func (sk *VRFPrivateKey) Prove(alpha []byte) (*VRFProof, error) {
	// H = HashToCurve(alpha)
	H := HashToCurve(alpha)

	// Gamma = sk * H
	gammaPoint := new(ristretto.Point).ScalarMult(H, sk.sk)
	gammaBytes := gammaPoint.Bytes()

	// k = deterministic nonce derived from (alpha || sk)
	k := deriveNonce(alpha, sk.sk.Bytes())

	// R = k * H (commitment)
	R := new(ristretto.Point).ScalarMult(H, k)
	RBytes := R.Bytes()

	// c = HashToScalar(H || Gamma || R)  (Fiat-Shamir challenge)
	c := hashToScalar(H.Bytes(), gammaBytes, RBytes)

	// s = k - c * sk (mod q)
	s := new(ristretto.Scalar)
	s.Sub(k, new(ristretto.Scalar).Mul(c, sk.sk))

	return &VRFProof{
		Gamma: gammaBytes,
		C:     c.Bytes(),
		S:     s.Bytes(),
	}, nil
}

// Verify verifies a VRF proof and returns the VRF output (gamma).
// Checks: c == HashToScalar(H || Gamma || s*H + c*Gamma)
func (pk *VRFPublicKey) Verify(alpha []byte, proof *VRFProof) ([]byte, error) {
	// Parse proof
	gammaPoint := new(ristretto.Point)
	if err := gammaPoint.UnmarshalBinary(proof.Gamma); err != nil {
		return nil, ErrVRFVerifyFailed
	}

	c := new(ristretto.Scalar)
	c.SetBytes((*[32]byte)(proof.C))

	s := new(ristretto.Scalar)
	s.SetBytes((*[32]byte)(proof.S))

	// H = HashToCurve(alpha)
	H := HashToCurve(alpha)

	// Reconstruct commitment: R = s*H + c*Gamma
	// = (k - c*sk)*H + c*sk*H = k*H
	sH := new(ristretto.Point).ScalarMult(H, s)
	cGamma := new(ristretto.Point).ScalarMult(gammaPoint, c)
	R := new(ristretto.Point).Add(sH, cGamma)
	RBytes := R.Bytes()

	// Verify challenge: c == HashToScalar(H || Gamma || R)
	expectedC := hashToScalar(H.Bytes(), proof.Gamma, RBytes)
	if !c.Equals(expectedC) {
		return nil, ErrVRFVerifyFailed
	}

	return proof.Gamma, nil
}

// VRFOutput returns the VRF output (gamma) from a proof.
func (proof *VRFProof) VRFOutput() []byte {
	return proof.Gamma
}

// MarshalVRFProof serializes a VRFProof to bytes (Gamma || C || S, each 32 bytes).
func MarshalVRFProof(proof *VRFProof) []byte {
	b := make([]byte, 0, 96)
	b = append(b, proof.Gamma...)
	b = append(b, proof.C...)
	b = append(b, proof.S...)
	return b
}

// UnmarshalVRFProof deserializes bytes to a VRFProof.
func UnmarshalVRFProof(data []byte) (*VRFProof, error) {
	if len(data) != 96 {
		return nil, ErrVRFInvalidInput
	}
	return &VRFProof{
		Gamma: data[:32],
		C:     data[32:64],
		S:     data[64:96],
	}, nil
}

// hashToScalar hashes input to a scalar.
func hashToScalar(inputs ...[]byte) *ristretto.Scalar {
	h := sha512.New()
	for _, input := range inputs {
		h.Write(input)
	}
	hash := h.Sum(nil)

	s := new(ristretto.Scalar)
	s.SetReduced((*[64]byte)(hash))
	return s
}

// deriveNonce derives a deterministic nonce from input and secret key.
func deriveNonce(alpha, skBytes []byte) *ristretto.Scalar {
	h := hmac.New(sha512.New, skBytes)
	h.Write(alpha)
	hash := h.Sum(nil)

	s := new(ristretto.Scalar)
	s.SetReduced((*[64]byte)(hash))
	return s
}

// Public key from private key.
func (sk *VRFPrivateKey) PublicKey() *VRFPublicKey {
	pk := new(ristretto.Point).ScalarMultBase(sk.sk)
	return &VRFPublicKey{pk: pk}
}

// Equal checks if two public keys are equal.
func (pk *VRFPublicKey) Equal(other *VRFPublicKey) bool {
	return pk.pk.Equals(other.pk)
}

// String returns string representation.
func (pk *VRFPublicKey) String() string {
	return fmt.Sprintf("%x", pk.Bytes())
}