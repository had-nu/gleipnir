// ECVRF-DLEQ implementation over Ristretto255, following the structure of
// RFC 9381 (§5.4.1.2, the ECVRF-EDWARDS25519-SHA512-TAI/DLEQ family).
//
// Proof shape and wire format are the RFC's: pi = (Gamma, c, s), three 32-byte
// scalars/points, so MarshalVRFProof still emits 96 bytes.
//
// Proof generation:
//
//	x = secret scalar,  Y = x*B  (the registered VRF public key)
//	H    = hash_to_curve(alpha)
//	Gamma = x*H
//	k    = ECVRF_nonce_generation(x, alpha)
//	U    = k*B,  V = k*H
//	c    = hash_to_scalar(Y || H || Gamma || U || V)
//	s    = k + c*x  (mod l)
//
// Verification recomputes U and V from (c, s) and the public key:
//
//	U = s*B - c*Y
//	V = s*H - c*Gamma
//	c == hash_to_scalar(Y || H || Gamma || U || V)
//
// The earlier implementation in this file verified only V = s*H + c*Gamma with a
// challenge c = hash(H || Gamma || R) that did not contain Y. That equation is
// satisfied by any Schnorr proof of knowledge of *a* discrete log for Gamma, so
// Verify never consulted the receiver: a proof produced under one key verified
// against every key in the system. The Y term in the challenge and the U equation
// are what bind a proof to the key that is supposed to have produced it.
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
	ErrVRFVerifyFailed = errors.New("VRF verification failed")
	ErrVRFInvalidInput = errors.New("VRF invalid input")

	// ErrVRFIdentityPoint is returned when a required Ristretto255 point decodes to
	// the identity element. RFC 9381 §5.4.1.2 requires Y, H, Gamma, U and V all to
	// be non-identity; accepting identity here would let a caller force
	// U = s*B - c*Y and V = s*H - c*Gamma to a known value and forge a proof.
	ErrVRFIdentityPoint = errors.New("VRF point is the identity element")
)

// VRFSuiteID is the ciphersuite identifier for VRF. It is the domain separation
// tag for hash-to-curve, per the hash-to-curve suite of the same name.
const VRFSuiteID = "ristretto255_XMD:SHA-512_R255MAP_RO_"

// vrfChallengeDST is the domain separation tag for hash_to_scalar, the challenge
// c. It is distinct from VRFSuiteID so that a value produced by hash-to-curve can
// never be replayed as a challenge, or vice versa. RFC 9381 §5.4.1.2 fixes the
// tag to the suite's own DST; keeping them separate is the conservative reading
// and costs nothing, since both tags are compiled in.
const vrfChallengeDST = VRFSuiteID + "challenge"

// VRFProofSize is the encoded proof length in bytes: Gamma || c || s.
const VRFProofSize = 96

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
	Gamma []byte // VRF output: x*H, the value callers actually consume
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
//
// SetBytes reduces modulo the group order l rather than rejecting, which is the
// correct choice for a key that was itself produced by reduction (see
// GenerateVRFKeyFromSeed). Two distinct byte strings therefore map to the same
// key; callers must not treat these bytes as a unique identifier.
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
	if isIdentity(pk) {
		return nil, ErrVRFIdentityPoint
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

// HashToCurve hashes input to a Ristretto255 point (HashToCurve).
// Uses expand_message_xmd with SHA-512 and Elligator2 mapping.
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

// Prove generates a DLEQ VRF proof for the given input.
//
// The proof commits to the secret key through the Y term of the challenge and
// the U equation, so Verify fails against any public key other than
// sk.PublicKey().
func (sk *VRFPrivateKey) Prove(alpha []byte) (*VRFProof, error) {
	if sk == nil || sk.sk == nil {
		return nil, ErrVRFInvalidInput
	}

	H := HashToCurve(alpha)
	if isIdentity(H) {
		return nil, ErrVRFIdentityPoint
	}
	y := new(ristretto.Point).ScalarMultBase(sk.sk)
	if isIdentity(y) {
		return nil, ErrVRFIdentityPoint
	}
	gamma := new(ristretto.Point).ScalarMult(H, sk.sk)
	if isIdentity(gamma) {
		return nil, ErrVRFIdentityPoint
	}

	// Nonce derivation is deterministic so that a given (key, alpha) pair always
	// yields the same proof and output. RFC 9381 §5.4.2.2 derives the nonce from a
	// truncated hash of the secret seed and alpha; HMAC-SHA-512 keyed by the secret
	// over a domain-separated alpha is the standard PRF form of the same
	// construction and is what this implementation uses.
	k := deriveNonce(alpha, sk.sk.Bytes())

	u := new(ristretto.Point).ScalarMultBase(k)
	v := new(ristretto.Point).ScalarMult(H, k)
	if isIdentity(u) || isIdentity(v) {
		return nil, ErrVRFIdentityPoint
	}

	c := hashToScalar(y.Bytes(), H.Bytes(), gamma.Bytes(), u.Bytes(), v.Bytes())

	// s = k + c*x (mod l)
	s := new(ristretto.Scalar).MulAdd(c, sk.sk, k)

	return &VRFProof{
		Gamma: append([]byte(nil), gamma.Bytes()...),
		C:     append([]byte(nil), c.Bytes()...),
		S:     append([]byte(nil), s.Bytes()...),
	}, nil
}

// Verify verifies a VRF proof and returns the VRF output (gamma).
//
// The public key on which this is called is part of the verification: a proof
// made under a different secret key recomputes a different challenge and is
// rejected with ErrVRFVerifyFailed.
//
// Checks, per RFC 9381 §5.4.1.2:
//  1. Y, H, Gamma are non-identity and decode canonically.
//  2. c and s are canonically reduced scalars (< l).
//  3. U = s*B - c*Y and V = s*H - c*Gamma are non-identity.
//  4. c == hash_to_scalar(Y || H || Gamma || U || V).
func (pk *VRFPublicKey) Verify(alpha []byte, proof *VRFProof) ([]byte, error) {
	if pk == nil || pk.pk == nil || proof == nil {
		return nil, ErrVRFVerifyFailed
	}
	if len(proof.Gamma) != 32 || len(proof.C) != 32 || len(proof.S) != 32 {
		return nil, ErrVRFVerifyFailed
	}
	if isIdentity(pk.pk) {
		return nil, ErrVRFVerifyFailed
	}

	// Canonical scalar decoding. SetBytes reduces modulo l, so it would accept
	// c + l as a synonym for c and make proofs malleable: two byte strings would
	// verify for one logical proof. SetBytesStrict rejects any non-reduced
	// encoding instead.
	cBuf := (*[32]byte)(proof.C)
	sBuf := (*[32]byte)(proof.S)
	c := new(ristretto.Scalar)
	if !c.SetBytesStrict(cBuf) {
		return nil, ErrVRFVerifyFailed
	}
	s := new(ristretto.Scalar)
	if !s.SetBytesStrict(sBuf) {
		return nil, ErrVRFVerifyFailed
	}

	gammaPoint := new(ristretto.Point)
	if err := gammaPoint.UnmarshalBinary(proof.Gamma); err != nil {
		return nil, ErrVRFVerifyFailed
	}
	if isIdentity(gammaPoint) {
		return nil, ErrVRFVerifyFailed
	}

	H := HashToCurve(alpha)
	if isIdentity(H) {
		return nil, ErrVRFVerifyFailed
	}

	// s, c and both points are public at verification time, so variable-time
	// scalar multiplication is the correct (and faster) choice here.
	yBytes := pk.pk.Bytes()
	hBytes := H.Bytes()

	// U = s*B - c*Y
	sB := new(ristretto.Point).PublicScalarMultBase(s)
	cY := new(ristretto.Point).PublicScalarMult(pk.pk, c)
	u := new(ristretto.Point).Sub(sB, cY)

	// V = s*H - c*Gamma
	sH := new(ristretto.Point).PublicScalarMult(H, s)
	cGamma := new(ristretto.Point).PublicScalarMult(gammaPoint, c)
	v := new(ristretto.Point).Sub(sH, cGamma)

	if isIdentity(u) || isIdentity(v) {
		return nil, ErrVRFVerifyFailed
	}

	expectedC := hashToScalar(yBytes, hBytes, proof.Gamma, u.Bytes(), v.Bytes())
	if !c.Equals(expectedC) {
		return nil, ErrVRFVerifyFailed
	}

	return append([]byte(nil), proof.Gamma...), nil
}

// VRFOutput returns the VRF output (gamma) from a proof.
func (proof *VRFProof) VRFOutput() []byte {
	return proof.Gamma
}

// MarshalVRFProof serializes a VRFProof to bytes (Gamma || C || S, each 32 bytes).
func MarshalVRFProof(proof *VRFProof) []byte {
	b := make([]byte, 0, VRFProofSize)
	b = append(b, proof.Gamma...)
	b = append(b, proof.C...)
	b = append(b, proof.S...)
	return b
}

// UnmarshalVRFProof deserializes bytes to a VRFProof.
//
// The fields are copied out of data. Slicing data directly would leave the proof
// aliasing the caller's buffer, so reusing or wiping that buffer would silently
// rewrite the proof's contents.
func UnmarshalVRFProof(data []byte) (*VRFProof, error) {
	if len(data) != VRFProofSize {
		return nil, ErrVRFInvalidInput
	}
	return &VRFProof{
		Gamma: append([]byte(nil), data[0:32]...),
		C:     append([]byte(nil), data[32:64]...),
		S:     append([]byte(nil), data[64:96]...),
	}, nil
}

// hashToScalar implements ECVRF hash_to_scalar: expand_message_xmd with SHA-512
// over the concatenated inputs, reduced modulo the group order l.
//
// Inputs are all fixed-width (32-byte point and scalar encodings) in every call
// site, so plain concatenation is unambiguous here.
func hashToScalar(inputs ...[]byte) *ristretto.Scalar {
	msg := make([]byte, 0, 32*len(inputs))
	for _, in := range inputs {
		msg = append(msg, in...)
	}

	xmd := expander.NewExpanderMD(crypto.SHA512, []byte(vrfChallengeDST))
	wide := xmd.Expand(msg, 64)

	var buf [64]byte
	copy(buf[:], wide)
	return new(ristretto.Scalar).SetReduced(&buf)
}

// deriveNonce derives a deterministic nonce from the input and secret key.
func deriveNonce(alpha, skBytes []byte) *ristretto.Scalar {
	h := hmac.New(sha512.New, skBytes)
	h.Write([]byte(vrfChallengeDST))
	h.Write(alpha)
	hash := h.Sum(nil)

	var buf [64]byte
	copy(buf[:], hash)
	return new(ristretto.Scalar).SetReduced(&buf)
}

// isIdentity reports whether p is the identity element of Ristretto255.
func isIdentity(p *ristretto.Point) bool {
	return p.Equals(new(ristretto.Point).SetZero())
}

// Public key from private key.
func (sk *VRFPrivateKey) PublicKey() *VRFPublicKey {
	pk := new(ristretto.Point).ScalarMultBase(sk.sk)
	return &VRFPublicKey{pk: pk}
}

// GenerateVRFKeyFromSeed generates a deterministic VRF keypair from a 32-byte seed.
//
// SetBytes reduces modulo l, so roughly 15/16 of all 32-byte seeds are accepted and
// folded into [0, l). That is deliberate and different from the strict decoding used
// on wire input: the seed is uniform output from HKDF, and rejecting the
// non-canonical majority here would make identity derivation fail unpredictably.
// The consequence is that the seed is not recoverable from the public key, which is
// fine for a seed-to-key map but means seeds must not be treated as key identifiers.
func GenerateVRFKeyFromSeed(seed [32]byte) (*VRFPrivateKey, *VRFPublicKey, error) {
	sk := new(ristretto.Scalar)
	sk.SetBytes(&seed)
	pk := new(ristretto.Point).ScalarMultBase(sk)
	return &VRFPrivateKey{sk: sk}, &VRFPublicKey{pk: pk}, nil
}

// Equal checks if two public keys are equal.
func (pk *VRFPublicKey) Equal(other *VRFPublicKey) bool {
	if pk == nil || other == nil || pk.pk == nil || other.pk == nil {
		return false
	}
	return pk.pk.Equals(other.pk)
}

// String returns string representation.
func (pk *VRFPublicKey) String() string {
	return fmt.Sprintf("%x", pk.Bytes())
}
