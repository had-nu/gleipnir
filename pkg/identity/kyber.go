// IPC identity — Kyber1024 KEM (post-quantum key encapsulation, ML-KEM-1024 per FIPS 203).
// Used for transport layer handshake.
package identity

import (
	"errors"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

const (
	Kyber1024PublicKeySize  = kyber1024.PublicKeySize  // 1568 bytes
	Kyber1024CiphertextSize = kyber1024.CiphertextSize // 1568 bytes
	Kyber1024SharedKeySize  = kyber1024.SharedKeySize  // 32 bytes
	Kyber1024SeedSize       = 64                       // 64 bytes (cpapke.KeySeedSize + 32)
)

// Aliases for backward compatibility during transition
const (
	Kyber768PublicKeySize  = Kyber1024PublicKeySize
	Kyber768CiphertextSize = Kyber1024CiphertextSize
	Kyber768SharedKeySize  = Kyber1024SharedKeySize
	Kyber768SeedSize       = Kyber1024SeedSize
)

var (
	ErrKyberInvalidKey    = errors.New("invalid Kyber key size")
	ErrKyberInvalidCT     = errors.New("invalid Kyber ciphertext size")
	ErrKyberDecapsulation = errors.New("Kyber decapsulation failed")
)

// GenerateKyberKeyPair generates a new Kyber1024 keypair.
func GenerateKyberKeyPair() (publicKey []byte, secretKey []byte, err error) {
	pk, sk, err := kyber1024.GenerateKeyPair(nil)
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pkBytes, skBytes, nil
}

// GenerateKyberKeyPairFromSeed generates a deterministic Kyber1024 keypair from seed.
func GenerateKyberKeyPairFromSeed(seed []byte) (publicKey []byte, secretKey []byte, err error) {
	if len(seed) != Kyber1024SeedSize {
		return nil, nil, errors.New("seed must be exactly 64 bytes")
	}
	pk, sk := kyber1024.NewKeyFromSeed(seed)
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pkBytes, skBytes, nil
}

// Encapsulate performs KEM encapsulation: generates shared secret and ciphertext.
func Encapsulate(publicKey []byte) (sharedSecret []byte, ciphertext []byte, err error) {
	if len(publicKey) != Kyber1024PublicKeySize {
		return nil, nil, ErrKyberInvalidKey
	}

	pk := new(kyber1024.PublicKey)
	pk.Unpack(publicKey)

	ct := make([]byte, Kyber1024CiphertextSize)
	ss := make([]byte, Kyber1024SharedKeySize)
	pk.EncapsulateTo(ct, ss, nil)

	return ss, ct, nil
}

// Decapsulate performs KEM decapsulation: recovers shared secret from ciphertext.
func Decapsulate(secretKey []byte, ciphertext []byte) (sharedSecret []byte, err error) {
	if len(secretKey) != kyber1024.PrivateKeySize {
		return nil, ErrKyberInvalidKey
	}
	if len(ciphertext) != Kyber1024CiphertextSize {
		return nil, ErrKyberInvalidCT
	}

	sk := new(kyber1024.PrivateKey)
	sk.Unpack(secretKey)

	ss := make([]byte, Kyber1024SharedKeySize)
	sk.DecapsulateTo(ss, ciphertext)

	return ss, nil
}