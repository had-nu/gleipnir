// IPC identity — Kyber768 KEM (post-quantum key encapsulation).
// Used for transport layer handshake (future milestone).
package identity

import (
	"errors"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

const (
	Kyber768PublicKeySize  = kyber768.PublicKeySize  // 1184 bytes
	Kyber768CiphertextSize = kyber768.CiphertextSize // 1088 bytes
	Kyber768SharedKeySize  = kyber768.SharedKeySize  // 32 bytes
	Kyber768SeedSize       = 64                      // 64 bytes (cpapke.KeySeedSize + 32)
)

var (
	ErrKyberInvalidKey    = errors.New("invalid Kyber key size")
	ErrKyberInvalidCT     = errors.New("invalid Kyber ciphertext size")
	ErrKyberDecapsulation = errors.New("Kyber decapsulation failed")
)

// GenerateKyberKeyPair generates a new Kyber768 keypair.
func GenerateKyberKeyPair() (publicKey []byte, secretKey []byte, err error) {
	pk, sk, err := kyber768.GenerateKeyPair(nil)
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

// GenerateKyberKeyPairFromSeed generates a deterministic Kyber768 keypair from seed.
func GenerateKyberKeyPairFromSeed(seed []byte) (publicKey []byte, secretKey []byte, err error) {
	if len(seed) != Kyber768SeedSize {
		return nil, nil, errors.New("seed must be exactly 64 bytes")
	}
	pk, sk := kyber768.NewKeyFromSeed(seed)
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
	if len(publicKey) != Kyber768PublicKeySize {
		return nil, nil, ErrKyberInvalidKey
	}

	pk := new(kyber768.PublicKey)
	pk.Unpack(publicKey)

	ct := make([]byte, Kyber768CiphertextSize)
	ss := make([]byte, Kyber768SharedKeySize)
	pk.EncapsulateTo(ct, ss, nil)

	return ss, ct, nil
}

// Decapsulate performs KEM decapsulation: recovers shared secret from ciphertext.
func Decapsulate(secretKey []byte, ciphertext []byte) (sharedSecret []byte, err error) {
	if len(secretKey) != kyber768.PrivateKeySize {
		return nil, ErrKyberInvalidKey
	}
	if len(ciphertext) != Kyber768CiphertextSize {
		return nil, ErrKyberInvalidCT
	}

	sk := new(kyber768.PrivateKey)
	sk.Unpack(secretKey)

	ss := make([]byte, Kyber768SharedKeySize)
	sk.DecapsulateTo(ss, ciphertext)

	return ss, nil
}