// IPC identity — Dilithium3 post-quantum signatures (mode3).
package identity

import (
	"crypto/subtle"
	"errors"
	"io"
	"runtime"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

const (
	Dilithium3PublicKeySize  = mode3.PublicKeySize   // 1952 bytes
	Dilithium3SecretKeySize  = mode3.PrivateKeySize  // 4032 bytes
	Dilithium3SignatureSize  = mode3.SignatureSize   // 2700 bytes
	Dilithium3SeedSize       = mode3.SeedSize        // 32 bytes
)

var (
	ErrInvalidSeed        = errors.New("seed must be at least 48 bytes")
	ErrBatchSizeMismatch  = errors.New("messages, signatures, and publicKeys must have equal length")
)

// GenerateDilithiumKey generates a new Dilithium3 keypair using the provided entropy.
func GenerateDilithiumKey(rand io.Reader) (publicKey []byte, secretKey []byte, err error) {
	pk, sk, err := mode3.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	return pk.Bytes(), sk.Bytes(), nil
}

// GenerateDilithiumKeyFromSeed generates a deterministic Dilithium3 keypair from a 48-byte seed.
func GenerateDilithiumKeyFromSeed(seed []byte) (publicKey [1952]byte, secretKey []byte, err error) {
	if len(seed) != Dilithium3SeedSize {
		return [1952]byte{}, nil, ErrInvalidSeed
	}

	var seedArr [Dilithium3SeedSize]byte
	copy(seedArr[:], seed)
	pk, sk := mode3.NewKeyFromSeed(&seedArr)

	var pkArr [1952]byte
	copy(pkArr[:], pk.Bytes())
	return pkArr, sk.Bytes(), nil
}

// SignDilithium signs a message with Dilithium3.
func SignDilithium(skBytes []byte, msg []byte) []byte {
	sk := new(mode3.PrivateKey)
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil
	}
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, msg, sig)
	return sig
}

// VerifyDilithium verifies a Dilithium3 signature.
func VerifyDilithium(pkBytes []byte, msg []byte, sig []byte) bool {
	pk := new(mode3.PublicKey)
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return false
	}
	return mode3.Verify(pk, msg, sig)
}

// VerifyDilithiumBytes verifies a Dilithium3 signature (alias).
func VerifyDilithiumBytes(pkBytes []byte, msg []byte, sig []byte) bool {
	return VerifyDilithium(pkBytes, msg, sig)
}

// VerifyBatch verifies multiple Dilithium3 signatures in batch.
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