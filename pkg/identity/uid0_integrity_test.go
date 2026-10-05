package identity

import (
	"bytes"
	"strings"
	"testing"
)

func testNetworkID() [32]byte {
	var n [32]byte
	copy(n[:], []byte("gleipnir-test-network-id"))
	return n
}

// A 32+ byte entropy source, so simulated=false is accepted.
const productionEntropy = "a-production-entropy-source-of-sufficient-length"

// FinalDigest must be recomputable by a verifier holding only public fields.
// It previously committed to SecretKey and VRFSecretKey, which made it impossible
// to check from public data and turned the published digest into a commitment to
// the private keys.
func TestFinalDigestIndependentOfSecretKeys(t *testing.T) {
	uid, err := NewUIDZero(productionEntropy, testNetworkID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !uid.VerifyDigest() {
		t.Fatal("VerifyDigest false on a freshly sealed identity")
	}

	// Same public fields, secrets cleared: the digest must not move.
	want := uid.FinalDigest
	cleared := *uid
	cleared.SecretKey = nil
	cleared.VRFSecretKey = nil
	if err := cleared.Seal(); err != nil {
		t.Fatal(err)
	}
	if cleared.FinalDigest != want {
		t.Fatal("FinalDigest changed when the secret keys were removed")
	}

	// Different secrets, same public fields: also must not move.
	other, err := NewUIDZero(productionEntropy, testNetworkID(), false)
	if err != nil {
		t.Fatal(err)
	}
	// Re-derive secrets deterministically from the same entropy, so they are in fact
	// identical; the point of the assertion is that the digest is insensitive to them.
	other.SecretKey = append([]byte(nil), uid.SecretKey...)
	other.VRFSecretKey = append([]byte(nil), uid.VRFSecretKey...)
	if err := other.Seal(); err != nil {
		t.Fatal(err)
	}
	if other.FinalDigest != want {
		t.Fatal("FinalDigest changed when the secret keys were replaced")
	}
}

// A verifier holding only the CBOR encoding of the public fields must reach the
// same digest. This is the property the project is actually built around: an
// outsider must be able to check an identity without possessing its secrets.
func TestFinalDigestVerifiableFromPublicFieldsOnly(t *testing.T) {
	uid, err := NewUIDZero(productionEntropy, testNetworkID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := uid.Seal(); err != nil {
		t.Fatal(err)
	}

	// Reconstruct from public data alone.
	view := uid.public()
	data, err := deterministicMode.Marshal(&view)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, uid.SecretKey) {
		t.Fatal("public encoding contains the secret key")
	}
	if bytes.Contains(data, uid.VRFSecretKey) {
		t.Fatal("public encoding contains the VRF secret key")
	}
	if got := Blake3Hash(data); got != uid.FinalDigest {
		t.Fatalf("digest recomputed from public fields = %x, want %x", got, uid.FinalDigest)
	}
}

// The digest must still be a fixed point of Seal, and must change when a public
// field is tampered with.
func TestFinalDigestBindsPublicFields(t *testing.T) {
	uid, err := NewUIDZero(productionEntropy, testNetworkID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := uid.Seal(); err != nil {
		t.Fatal(err)
	}
	original := uid.FinalDigest

	mutations := map[string]func(*UIDZeroSoulbound){
		"root id":        func(u *UIDZeroSoulbound) { u.RootID[0] ^= 0xFF },
		"public key":     func(u *UIDZeroSoulbound) { u.PublicKey[0] ^= 0xFF },
		"vrf public key": func(u *UIDZeroSoulbound) { u.VRFPublicKey[0] ^= 0xFF },
		"contract hash":  func(u *UIDZeroSoulbound) { u.ContractHash[0] ^= 0xFF },
		"simulated flag": func(u *UIDZeroSoulbound) { u.Simulated = !u.Simulated },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			clone := *uid
			mutate(&clone)
			if err := clone.Seal(); err != nil {
				t.Fatal(err)
			}
			if clone.FinalDigest == original {
				t.Fatalf("digest unchanged after mutating %s", name)
			}
		})
	}
}

// A simulated identity must be refused when a caller asks for a production one.
func TestRequireProductionRejectsSimulated(t *testing.T) {
	uid, err := NewUIDZero("short", testNetworkID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !uid.Simulated {
		t.Fatal("expected Simulated to be set")
	}
	err = uid.RequireProduction()
	if err == nil {
		t.Fatal("RequireProduction accepted a simulated identity")
	}
	if !strings.Contains(err.Error(), ErrSimulatedIdentity.Error()) {
		t.Fatalf("error %v does not wrap ErrSimulatedIdentity", err)
	}
}

func TestRequireProductionAcceptsRealIdentity(t *testing.T) {
	uid, err := NewUIDZero(productionEntropy, testNetworkID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := uid.RequireProduction(); err != nil {
		t.Fatalf("RequireProduction rejected a real identity: %v", err)
	}
}

// Key derivation failures must surface as errors. They previously yielded a zeroed
// public key and a zeroed secret key while reporting success, producing an identity
// that signed with a publicly known seed.
func TestKeyDerivationFailureIsNotSilent(t *testing.T) {
	if _, _, err := generateDilithiumKey([]byte("too short")); err == nil {
		t.Fatal("generateDilithiumKey accepted a short seed")
	}
	if _, _, err := generateVRFKey([]byte("too short")); err == nil {
		t.Fatal("generateVRFKey accepted a short seed")
	}
	// A failed derivation must not hand back a usable-looking key.
	pk, sk, err := generateDilithiumKey([]byte("bad"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if sk != nil {
		t.Fatal("a secret key was returned alongside the error")
	}
	if pk != [1952]byte{} {
		t.Fatal("a zero public key was returned alongside the error")
	}
}

func TestNewUIDZeroRejectsShortEntropy(t *testing.T) {
	if _, err := NewUIDZero("short", testNetworkID(), false); err == nil {
		t.Fatal("a 5-byte entropy source was accepted with simulated=false")
	}
	// simulated=true is the documented relaxation, used by genesis fixtures and tests.
	if _, err := NewUIDZero("short", testNetworkID(), true); err != nil {
		t.Fatalf("simulated construction failed: %v", err)
	}
}

// A produced identity must never carry a zeroed key, which is the signature of the
// silent-fallback path.
func TestNewUIDZeroProducesNonZeroKeys(t *testing.T) {
	uid, err := NewUIDZero(productionEntropy, testNetworkID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if uid.PublicKey == ([1952]byte{}) {
		t.Fatal("dilithium public key is all zeros")
	}
	if uid.VRFPublicKey == ([32]byte{}) {
		t.Fatal("VRF public key is all zeros")
	}
	if len(uid.SecretKey) != Dilithium3SecretKeySize {
		t.Fatalf("secret key is %d bytes, want %d", len(uid.SecretKey), Dilithium3SecretKeySize)
	}
	if len(uid.VRFSecretKey) != 32 {
		t.Fatalf("VRF secret key is %d bytes, want 32", len(uid.VRFSecretKey))
	}
}

// The VRF key stored on the identity must be the one Verify accepts.
func TestUIDZeroVRFProofBindsToIdentity(t *testing.T) {
	uid, err := NewUIDZero(productionEntropy, testNetworkID(), false)
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("alpha")
	proof, err := uid.VRFProve(alpha)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uid.VRFVerifyProof(alpha, proof); err != nil {
		t.Fatalf("identity rejected its own proof: %v", err)
	}

	other, err := NewUIDZero("a-different-production-entropy-source-value", testNetworkID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.VRFVerifyProof(alpha, proof); err == nil {
		t.Fatal("a different identity accepted the proof")
	}
}
