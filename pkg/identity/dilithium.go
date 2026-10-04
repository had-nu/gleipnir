// IPC identity — ML-DSA-65 (Dilithium3) post-quantum signatures, FIPS 204.
//
// 3CP v2.0 §4.2 mandates ML-DSA-65 "conforme FIPS 204": a 1952-byte verifying
// key, a 4032-byte expanded signing key and a 3309-byte signature at NIST
// security level 3 (AES-192 equivalent).
//
// The private key is handled here in its canonical FIPS 204 §3.1 seed form
// (32 bytes) rather than the expanded form. FIPS 204 states that the seed is a
// valid signing key format, and it is the stronger of the two: the whole value
// contributes to every derived component, so a malformed expanded key cannot be
// constructed by an attacker, whereas a cached expanded key must be validated
// before use. crypto/mldsa exposes only the seed form, so the expanded key is
// re-derived on demand — see SignDilithium for the performance note.
//
// Signing is deterministic (ML-DSA.Sign_internal with rnd = 0), which keeps
// genesis and the published test vectors byte-reproducible. FIPS 204's default
// is hedged signing, which is stronger against fault injection; that trade-off is
// deliberate and recorded here rather than left implicit.
package identity

import (
	cryptorand "crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"runtime"

	"crypto/mldsa"
)

// FIPS 204 Table 2 sizes for ML-DSA-65.
//
// These are constants rather than calls to mldsaParams.SignatureSize() because
// callers use them as array lengths (e.g. chain.KeyRotationPublicKeySize).
// TestMLDSA65SizesMatchFIPS204 asserts they still agree with crypto/mldsa, so a
// change in the standard library cannot silently desynchronise the wire format
// from the primitives.
const (
	// Dilithium3PublicKeySize is the ML-DSA-65 verifying key size (1952 bytes).
	Dilithium3PublicKeySize = 1952

	// Dilithium3SecretKeySize is the signing key size in its seed form (32 bytes).
	// The expanded FIPS 204 form is 4032 bytes; it is derived internally and never
	// stored or serialised.
	Dilithium3SecretKeySize = 32

	// Dilithium3SignatureSize is the ML-DSA-65 signature size (3309 bytes).
	Dilithium3SignatureSize = 3309

	// Dilithium3SeedSize is the ML-DSA.KeyGen seed size ξ (32 bytes).
	Dilithium3SeedSize = 32
)

// mldsaParams is the ML-DSA-65 parameter set mandated by 3CP v2.0 §4.2.
var mldsaParams = mldsa.MLDSA65()

var (
	// ErrInvalidSeed is returned when a seed is not exactly Dilithium3SeedSize bytes.
	ErrInvalidSeed = errors.New("seed must be exactly 32 bytes")

	// ErrInvalidSecretKey is returned when a signing key is not a valid ML-DSA-65
	// seed.
	ErrInvalidSecretKey = errors.New("invalid ML-DSA-65 secret key")

	// ErrBatchSizeMismatch is returned when batch inputs have unequal length.
	ErrBatchSizeMismatch = errors.New("messages, signatures, and publicKeys must have equal length")
)

// GenerateDilithiumKey generates a new ML-DSA-65 keypair using the provided entropy.
// A nil reader means crypto/rand. The returned secret key is the 32-byte seed.
func GenerateDilithiumKey(rand io.Reader) (publicKey []byte, secretKey []byte, err error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	seed := make([]byte, Dilithium3SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	var pk [Dilithium3PublicKeySize]byte
	pk, sk, err := GenerateDilithiumKeyFromSeed(seed)
	if err != nil {
		return nil, nil, err
	}
	return pk[:], sk, nil
}

// GenerateDilithiumKeyFromSeed deterministically derives an ML-DSA-65 keypair from a
// 32-byte seed. Identical seeds always yield identical keys and signatures.
//
// The caller's seed is read but never modified.
func GenerateDilithiumKeyFromSeed(seed []byte) (publicKey [Dilithium3PublicKeySize]byte, secretKey []byte, err error) {
	if len(seed) != Dilithium3SeedSize {
		return [Dilithium3PublicKeySize]byte{}, nil, ErrInvalidSeed
	}

	sk, err := mldsa.NewPrivateKey(mldsaParams, seed)
	if err != nil {
		return [Dilithium3PublicKeySize]byte{}, nil, err
	}

	copy(publicKey[:], sk.PublicKey().Bytes())
	// sk.Bytes() is the canonical seed form; copy so the caller cannot alias
	// library-owned memory.
	secretKey = append([]byte(nil), sk.Bytes()...)

	return publicKey, secretKey, nil
}

// SignDilithium signs a message with an ML-DSA-65 key in seed form, returning nil on
// any error so that callers can treat a short or nil signature as invalid.
//
// PERFORMANCE: crypto/mldsa exposes only the seed form, so the expanded key is
// re-derived on every call (~0.8 ms) on top of the signature itself (~3.0 ms).
// That is roughly 4.7x slower than the round-3 circl implementation this replaced
// and matters on the PREPARE/COMMIT co-signing path. Callers that sign many
// messages in a tight loop should hold an *mldsa.PrivateKey and call
// SignDeterministic directly rather than going through this helper.
func SignDilithium(skBytes []byte, msg []byte) []byte {
	if len(skBytes) != Dilithium3SecretKeySize {
		return nil
	}
	sk, err := mldsa.NewPrivateKey(mldsaParams, skBytes)
	if err != nil {
		return nil
	}
	sig, err := sk.SignDeterministic(msg, nil)
	if err != nil {
		return nil
	}
	return sig
}

// VerifyDilithium verifies an ML-DSA-65 signature. It reports false for malformed
// keys or signatures of the wrong length rather than panicking, so untrusted wire
// input can be passed directly.
func VerifyDilithium(pkBytes []byte, msg []byte, sig []byte) bool {
	if len(pkBytes) != Dilithium3PublicKeySize || len(sig) != Dilithium3SignatureSize {
		return false
	}
	pk, err := mldsa.NewPublicKey(mldsaParams, pkBytes)
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig, nil) == nil
}

// VerifyDilithiumBytes verifies an ML-DSA-65 signature (alias).
func VerifyDilithiumBytes(pkBytes []byte, msg []byte, sig []byte) bool {
	return VerifyDilithium(pkBytes, msg, sig)
}

// VerifyBatch verifies multiple ML-DSA-65 signatures.
// Returns a slice of bool results (true = valid) and an error if inputs are invalid.
func VerifyBatch(messages [][]byte, signatures [][]byte, publicKeys [][]byte) ([]bool, error) {
	if len(messages) != len(signatures) || len(signatures) != len(publicKeys) {
		return nil, ErrBatchSizeMismatch
	}

	results := make([]bool, len(messages))
	for i := range messages {
		results[i] = VerifyDilithium(publicKeys[i], messages[i], signatures[i])
	}
	return results, nil
}

// WipeSecret securely erases a secret key from memory.
func WipeSecret(sk []byte) {
	if len(sk) == 0 {
		return
	}
	zeros := make([]byte, len(sk))
	subtle.ConstantTimeCopy(1, sk, zeros)
	runtime.KeepAlive(sk)
}
