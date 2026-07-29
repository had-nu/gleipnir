package identity

import (
	"bytes"
	"testing"
)

func TestContractHashDeterministic(t *testing.T) {
	doc := []byte("GLEIPNIR FOUNDING CONTRACT — internal services accountability fabric")
	h1 := ContractHash(doc)
	h2 := ContractHash(doc)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("ContractHash not deterministic")
	}
	if len(h1) != 32 {
		t.Fatalf("expected 32-byte contract hash, got %d", len(h1))
	}
}

func TestUIDZeroFromContractDeterministic(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("company-founding-doc-v1"))

	contract := ContractHash([]byte("company-founding-doc-v1"))

	a, err := NewUIDZeroFromContract(contract, "wardex", false)
	if err != nil {
		t.Fatalf("NewUIDZeroFromContract error: %v", err)
	}
	b, err := NewUIDZeroFromContract(contract, "wardex", false)
	if err != nil {
		t.Fatalf("NewUIDZeroFromContract error: %v", err)
	}

	// Same contract+salt must produce identical identity (incl. keypair)
	if a.ID() != b.ID() {
		t.Fatal("RootID not deterministic for same contract+salt")
	}
	if a.PublicKey != b.PublicKey {
		t.Fatal("PublicKey not deterministic for same contract+salt")
	}
	if !bytes.Equal(a.SecretKey, b.SecretKey) {
		t.Fatal("SecretKey not deterministic for same contract+salt")
	}
	if a.ContractOf() != contract {
		t.Fatal("ContractOf mismatch")
	}
}

func TestUIDZeroFromContractSaltDifferentiation(t *testing.T) {
	contract := ContractHash([]byte("company-founding-doc-v1"))

	wardex, err := NewUIDZeroFromContract(contract, "wardex", false)
	if err != nil {
		t.Fatalf("NewUIDZeroFromContract error: %v", err)
	}
	ransom, err := NewUIDZeroFromContract(contract, "anti-ransomware", false)
	if err != nil {
		t.Fatalf("NewUIDZeroFromContract error: %v", err)
	}

	if wardex.ID() == ransom.ID() {
		t.Fatal("different salts should produce different RootIDs")
	}
	if wardex.PublicKey == ransom.PublicKey {
		t.Fatal("different salts should produce different keypairs")
	}
}

func TestUIDZeroFromContractDifferentContract(t *testing.T) {
	c1 := ContractHash([]byte("contract-A"))
	c2 := ContractHash([]byte("contract-B"))

	a, err := NewUIDZeroFromContract(c1, "wardex", false)
	if err != nil {
		t.Fatalf("NewUIDZeroFromContract error: %v", err)
	}
	b, err := NewUIDZeroFromContract(c2, "wardex", false)
	if err != nil {
		t.Fatalf("NewUIDZeroFromContract error: %v", err)
	}

	if a.ID() == b.ID() {
		t.Fatal("different contracts should produce different identities")
	}
}

func TestRandomUIDZeroHasNoContract(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("random-network-id"))
	uid, err := NewUIDZero("random-seed", networkID, true)
	if err != nil {
		t.Fatalf("NewUIDZero error: %v", err)
	}
	if uid.ContractOf() == [32]byte{} {
		t.Fatal("random UID0 should not be contract-bound")
	}
}