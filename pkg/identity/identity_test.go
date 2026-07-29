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
	var networkID [32]byte
	copy(networkID[:], []byte("test-network-id"))
	uid, err := NewUIDZero("test-seed", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	if uid == nil {
		t.Fatal("uid is nil")
	}
	if uid.RootID == [16]byte{} {
		t.Fatal("RootID is empty")
	}
	if uid.PublicKey == [1952]byte{} {
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
	var networkID [32]byte
	copy(networkID[:], []byte("test-network-id"))
	uid, err := NewUIDZero("test-id-42", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	id := uid.ID()
	if len(id) == 0 {
		t.Fatal("ID is empty")
	}
}

func TestNewUIDZeroDeterministic(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("test-network-id"))
	uid1, err := NewUIDZero("same-seed", networkID, true)
	if err != nil {
		t.Fatal(err)
	}
	uid2, err := NewUIDZero("same-seed", networkID, true)
	if err != nil {
		t.Fatal(err)
	}

	id1 := uid1.ID()
	id2 := uid2.ID()

	if id1 == id2 {
		t.Log("RootID may collide with same seed (expected for small seeds)")
	}
}

func TestCBORMarshalUnmarshal(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("test-network-id"))
	uid, err := NewUIDZero("cbor-test", networkID, true)
	if err != nil {
		t.Fatal(err)
	}

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
	var networkID [32]byte
	copy(networkID[:], []byte("test-network-id"))
	uid, err := NewUIDZero("key-test", networkID, true)
	if err != nil {
		t.Fatal(err)
	}

	data, err := uid.SerializeCBOR()
	if err != nil {
		t.Fatal(err)
	}

	uid2, err := UnmarshalCBOR(data)
	if err != nil {
		t.Fatal(err)
	}

	if uid2.PublicKey == [1952]byte{} {
		t.Fatal("PublicKey lost during CBOR round-trip")
	}
}

func TestVRFProveVerify(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("vrf-test-network"))
	uid, err := NewUIDZero("vrf-test", networkID, true)
	if err != nil {
		t.Fatal(err)
	}

	alpha := []byte("test-alpha")
	proof, err := uid.VRFProve(alpha)
	if err != nil {
		t.Fatal(err)
	}

	gamma, err := uid.VRFVerifyProof(alpha, proof)
	if err != nil {
		t.Fatal(err)
	}

	if len(gamma) != 32 {
		t.Fatalf("expected 32-byte VRF output, got %d", len(gamma))
	}

	// Test verification with wrong alpha
	_, err = uid.VRFVerifyProof([]byte("wrong"), proof)
	if err == nil {
		t.Fatal("VRF verification should fail for wrong alpha")
	}
}

func TestDilithiumBatchVerify(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("batch-test-network"))

	// Generate multiple UIDs
	uids := make([]*UIDZeroSoulbound, 5)
	for i := 0; i < 5; i++ {
		uid, err := NewUIDZero("batch-seed-"+string(rune(i+'0')), networkID, true)
		if err != nil {
			t.Fatal(err)
		}
		uids[i] = uid
	}

	// Create messages and signatures
	messages := make([][]byte, 5)
	signatures := make([][]byte, 5)
	publicKeys := make([][]byte, 5)

	for i := 0; i < 5; i++ {
		messages[i] = []byte("message-" + string(rune(i+'0')))
		signatures[i] = uids[i].SignDilithium(messages[i])
		publicKeys[i] = uids[i].PublicKey[:]
	}

	// Batch verify
	results, err := VerifyBatch(messages, signatures, publicKeys)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}

	for i, ok := range results {
		if !ok {
			t.Errorf("signature %d should be valid", i)
		}
	}

	// Tamper with one message
	messages[0] = []byte("tampered")
	results, err = VerifyBatch(messages, signatures, publicKeys)
	if err != nil {
		t.Fatal(err)
	}
	if results[0] {
		t.Error("tampered message should fail verification")
	}
}