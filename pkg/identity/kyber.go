package identity

import (
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"lukechampine.com/blake3"
)

// KyberDigest implements a pseudo-KDF using Kyber1024.
// The spec states: "Kyber1024 como função de derivação... derivam do shared secret
// de uma encapsulação efêmera, usando os inputs como dados de contexto para a encapsulação."
//
// In standard Kyber, Encapsulate generates a shared secret and ciphertext.
// Here we use the inputs to deterministically seed the encapsulation process
// to produce a stable "digest" (shared secret).
func KyberDigest(inputs ...[]byte) []byte {
	var combined []byte
	for _, in := range inputs {
		combined = append(combined, in...)
	}

	// generate 64 byte seed for DeriveKeyPair
	seed := blake3.Sum512(combined)

	pk, _ := kyber1024.Scheme().DeriveKeyPair(seed[:])

	// derive 32 byte seed for encapsulation
	encapCtx := append(combined, []byte("encap")...)
	encapSeed := blake3.Sum256(encapCtx)

	_, sharedSecret, _ := kyber1024.Scheme().EncapsulateDeterministically(pk, encapSeed[:])

	return sharedSecret
}
