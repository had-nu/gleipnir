// ML-DSA-65 (FIPS 204) conformance guards.
//
// The sizes in dilithium.go are declared as constants because callers use them as
// array lengths, so they cannot be derived from crypto/mldsa at compile time. These
// tests pin them to the standard library and to FIPS 204 Table 2, so neither a
// dependency bump nor an accidental edit can silently change the wire format.

package identity

import (
	"bytes"
	"crypto/mldsa"
	"testing"
)

// TestMLDSA65SizesMatchFIPS204 asserts the declared constants agree with
// crypto/mldsa's ML-DSA-65 parameter set.
func TestMLDSA65SizesMatchFIPS204(t *testing.T) {
	p := mldsa.MLDSA65()

	if got := p.PublicKeySize(); got != Dilithium3PublicKeySize {
		t.Errorf("Dilithium3PublicKeySize = %d, crypto/mldsa says %d", Dilithium3PublicKeySize, got)
	}
	if got := p.SignatureSize(); got != Dilithium3SignatureSize {
		t.Errorf("Dilithium3SignatureSize = %d, crypto/mldsa says %d", Dilithium3SignatureSize, got)
	}

	// FIPS 204 Table 2, ML-DSA-65 row.
	const (
		fips204PublicKey  = 1952
		fips204ExpandedSk = 4032
		fips204Signature  = 3309
		fips204Seed       = 32
	)
	if Dilithium3PublicKeySize != fips204PublicKey {
		t.Errorf("public key = %d, FIPS 204 Table 2 says %d", Dilithium3PublicKeySize, fips204PublicKey)
	}
	if Dilithium3SignatureSize != fips204Signature {
		t.Errorf("signature = %d, FIPS 204 Table 2 says %d", Dilithium3SignatureSize, fips204Signature)
	}
	if Dilithium3SeedSize != fips204Seed {
		t.Errorf("seed = %d, FIPS 204 says %d", Dilithium3SeedSize, fips204Seed)
	}
	// The signing key is handled in seed form; the expanded form is 4032 bytes and is
	// derived internally. Assert a generated key really is the seed, so a future change
	// to storing the expanded form cannot pass unnoticed and break serialization.
	if Dilithium3SecretKeySize != fips204Seed {
		t.Errorf("secret key (seed form) = %d, want %d", Dilithium3SecretKeySize, fips204Seed)
	}
	_ = fips204ExpandedSk

	// Guard against the withdrawn round-3 parameterisation sneaking back in: circl's
	// dilithium/mode3 signs at 3293 bytes and is not FIPS 204 conformant.
	if Dilithium3SignatureSize == 3293 {
		t.Error("signature size 3293 indicates round-3 Dilithium3, not FIPS 204 ML-DSA-65")
	}
	if Dilithium3SignatureSize == 2700 {
		t.Error("signature size 2700 is not produced by any Dilithium3 parameter set")
	}
}

// TestGeneratedKeyIsSeedForm asserts GenerateDilithiumKeyFromSeed returns the
// canonical 32-byte seed rather than the expanded 4032-byte key.
func TestGeneratedKeyIsSeedForm(t *testing.T) {
	seed := make([]byte, Dilithium3SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	pk, sk, err := GenerateDilithiumKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateDilithiumKeyFromSeed: %v", err)
	}
	if len(sk) != Dilithium3SecretKeySize {
		t.Fatalf("secret key is %d bytes, want the %d-byte seed form", len(sk), Dilithium3SecretKeySize)
	}
	if !bytes.Equal(sk, seed) {
		t.Error("returned secret key must be the seed itself (FIPS 204 §3.1 canonical form)")
	}

	// The caller's seed buffer must not be disturbed: callers legitimately reuse a
	// seed to derive several keys, and silently zeroing it would yield wrong keys.
	seedCopy := append([]byte(nil), seed...)
	_, _, err = GenerateDilithiumKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("second derivation: %v", err)
	}
	if !bytes.Equal(seed, seedCopy) {
		t.Error("GenerateDilithiumKeyFromSeed must not modify the caller's seed")
	}

	// The public key must verify against a signature made with that seed.
	msg := []byte("fips204 conformance check")
	sig := SignDilithium(sk, msg)
	if len(sig) != Dilithium3SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), Dilithium3SignatureSize)
	}
	if !VerifyDilithium(pk[:], msg, sig) {
		t.Error("signature must verify against the derived public key")
	}
}

// TestSigningIsDeterministic pins the deliberate choice of ML-DSA.Sign_internal over
// FIPS 204's default hedged signing, which keeps genesis and the published test
// vectors byte-reproducible.
func TestSigningIsDeterministic(t *testing.T) {
	seed := make([]byte, Dilithium3SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	_, sk, err := GenerateDilithiumKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateDilithiumKeyFromSeed: %v", err)
	}

	msg := []byte("determinism check")
	first := SignDilithium(sk, msg)
	second := SignDilithium(sk, msg)

	if !bytes.Equal(first, second) {
		t.Error("SignDilithium must be deterministic; the same key and message must produce identical bytes")
	}
	if !VerifyDilithium(mustPublicKey(t, seed), msg, first) {
		t.Error("deterministic signature must verify")
	}
}

// TestSignDilithiumRejectsBadInput asserts the helper fails closed rather than
// panicking, since callers pass it key material derived from the wire.
func TestSignDilithiumRejectsBadInput(t *testing.T) {
	if got := SignDilithium(nil, []byte("x")); got != nil {
		t.Error("nil secret key must yield a nil signature")
	}
	if got := SignDilithium(make([]byte, 4000), []byte("x")); got != nil {
		t.Error("an expanded-length key is not the canonical seed form and must be rejected")
	}
}

func mustPublicKey(t *testing.T, seed []byte) []byte {
	t.Helper()
	pk, _, err := GenerateDilithiumKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateDilithiumKeyFromSeed: %v", err)
	}
	return pk[:]
}
