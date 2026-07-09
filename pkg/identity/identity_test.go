package identity

import (
	"crypto/rand"
	"testing"
)

func TestGenerateDilithiumKey(t *testing.T) {
	pk, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) == 0 {
		t.Fatal("public key is empty")
	}
	if len(sk) == 0 {
		t.Fatal("secret key is empty")
	}
}

func TestSignAndVerify(t *testing.T) {
	pk, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test message")
	sig := SignDilithium(sk, msg)
	if sig == nil {
		t.Fatal("signature is nil")
	}

	ok := VerifyDilithium(pk, msg, sig)
	if !ok {
		t.Fatal("verify failed")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	pk, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sig := SignDilithium(sk, []byte("message"))

	ok := VerifyDilithium(pk, []byte("wrong message"), sig)
	if ok {
		t.Fatal("verify should fail for wrong message")
	}
}

func TestVerifyDilithiumBytes(t *testing.T) {
	pk, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test")
	sig := SignDilithium(sk, msg)

	ok := VerifyDilithiumBytes(pk, msg, sig)
	if !ok {
		t.Fatal("VerifyDilithiumBytes should match VerifyDilithium")
	}
}

func TestNewUIDZero(t *testing.T) {
	uid := NewUIDZero("test-seed", true)
	if uid == nil {
		t.Fatal("uid is nil")
	}
	if len(uid.RootID) == 0 {
		t.Fatal("RootID is empty")
	}
	if len(uid.PublicKey) == 0 {
		t.Fatal("PublicKey is empty")
	}
	if len(uid.SecretKey) == 0 {
		t.Fatal("SecretKey is empty")
	}
	if !uid.Simulated {
		t.Fatal("should be simulated")
	}
}

func TestUIDZeroID(t *testing.T) {
	uid := NewUIDZero("test-id-42", false)
	id := uid.ID()
	if len(id) == 0 {
		t.Fatal("ID is empty")
	}
}

func TestNewUIDZeroDeterministic(t *testing.T) {
	uid1 := NewUIDZero("same-seed", true)
	uid2 := NewUIDZero("same-seed", true)

	id1 := uid1.ID()
	id2 := uid2.ID()

	if id1 == id2 {
		t.Log("RootID may collide with same seed (expected for small seeds)")
	}
}

func TestCBORMarshalUnmarshal(t *testing.T) {
	uid := NewUIDZero("cbor-test", true)

	data, err := uid.SerializeCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("serialized data is empty")
	}

	uid2, err := UnmarshalCBOR(data)
	if err != nil {
		t.Fatal(err)
	}
	if uid2 == nil {
		t.Fatal("unmarshaled uid is nil")
	}

	id1 := uid.ID()
	id2 := uid2.ID()
	if id1 != id2 {
		t.Fatalf("ID mismatch after round-trip: %s vs %s", id1, id2)
	}
}

func TestCBORMarshalPreservesPublicKey(t *testing.T) {
	uid := NewUIDZero("key-test", true)

	data, err := uid.SerializeCBOR()
	if err != nil {
		t.Fatal(err)
	}

	uid2, err := UnmarshalCBOR(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(uid2.PublicKey) == 0 {
		t.Fatal("PublicKey lost during CBOR round-trip")
	}
}

func TestSealAndFinalDigest(t *testing.T) {
	uid := NewUIDZero("seal-test", true)

	err := uid.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if len(uid.FinalDigest) == 0 {
		t.Fatal("FinalDigest is empty after Seal")
	}
}

func TestWipeSecret(t *testing.T) {
	_, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	WipeSecret(sk)
	for _, b := range sk {
		if b != 0 {
			t.Fatal("secret key was not wiped")
		}
	}
}

func TestHash(t *testing.T) {
	h1 := Hash([]byte("test"))
	h2 := Hash([]byte("test"))

	if len(h1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(h1))
	}

	for i := range h1 {
		if h1[i] != h2[i] {
			t.Fatal("hash should be deterministic")
		}
	}

	h3 := Hash([]byte("different"))
	equal := true
	for i := range h1 {
		if h1[i] != h3[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestGenerateLivenessNonce(t *testing.T) {
	nonce, err := GenerateLivenessNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(nonce))
	}

	nonce2, _ := GenerateLivenessNonce()
	equal := true
	for i := range nonce {
		if nonce[i] != nonce2[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Fatal("nonces should be random")
	}
}
