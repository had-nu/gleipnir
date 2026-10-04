// ML-DSA-65 performance characteristics.
//
// The signing path re-derives the expanded key from its seed on every call, because
// crypto/mldsa exposes only the seed form of the signing key. These benchmarks exist
// to make that cost visible: it is the dominant regression from the FIPS 204
// migration (round-3 circl mode3 signed at roughly 0.6 ms; ML-DSA-65 signs at roughly
// 3.0 ms and re-derivation adds roughly 0.8 ms on top).
//
// If the PREPARE/COMMIT co-signing path ever needs the throughput back, callers should
// hold an *mldsa.PrivateKey and call SignDeterministic directly rather than going
// through identity.SignDilithium.
package identity

import (
	"crypto/mldsa"
	"testing"
)

var benchParams = mldsa.MLDSA65()

func benchSeed() []byte {
	seed := make([]byte, Dilithium3SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

// BenchmarkMLDSA65Keygen measures the cost of deriving an expanded key from its seed,
// which SignDilithium pays on every signature.
func BenchmarkMLDSA65Keygen(b *testing.B) {
	seed := benchSeed()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mldsa.NewPrivateKey(benchParams, seed); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLDSA65SignCachedKey measures the signature itself, with the expanded key
// already in hand. This is the floor for any signing implementation on this primitive.
func BenchmarkMLDSA65SignCachedKey(b *testing.B) {
	sk, err := mldsa.NewPrivateKey(benchParams, benchSeed())
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("block hash payload for signing")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sk.SignDeterministic(msg, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLDSA65Verify measures verification, the operation every validator performs
// for every peer signature and so the one that scales with validator count.
func BenchmarkMLDSA65Verify(b *testing.B) {
	sk, err := mldsa.NewPrivateKey(benchParams, benchSeed())
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("block hash payload for signing")
	sig, err := sk.SignDeterministic(msg, nil)
	if err != nil {
		b.Fatal(err)
	}
	pk := sk.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := mldsa.Verify(pk, msg, sig, nil); err != nil {
			b.Fatal(err)
		}
	}
}
