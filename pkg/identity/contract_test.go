package identity

import (
	"bytes"
	"testing"
)

func TestContractHashDeterministic(t *testing.T) {
	doc := []byte("GLEIPNIR FOUNDING CONTRACT — internal services accountability fabric")
	h1 := ContractHash(doc)
	h2 := ContractHash(doc)
	if !bytes.Equal(h1, h2) {
		t.Fatal("ContractHash not deterministic")
	}
	if len(h1) != 32 {
		t.Fatalf("expected 32-byte contract hash, got %d", len(h1))
	}
}

func TestUIDZeroFromContractDeterministic(t *testing.T) {
	contract := ContractHash([]byte("company-founding-doc-v1"))

	a := NewUIDZeroFromContract(contract, "wardex", false)
	b := NewUIDZeroFromContract(contract, "wardex", false)

	// Same contract+salt must produce identical identity (incl. keypair)
	if a.ID() != b.ID() {
		t.Fatal("RootID not deterministic for same contract+salt")
	}
	if !bytes.Equal(a.PublicKey, b.PublicKey) {
		t.Fatal("PublicKey not deterministic for same contract+salt")
	}
	if !bytes.Equal(a.SecretKey, b.SecretKey) {
		t.Fatal("SecretKey not deterministic for same contract+salt")
	}
	if !bytes.Equal(a.ContractOf(), contract) {
		t.Fatal("ContractOf mismatch")
	}
}

func TestUIDZeroFromContractSaltDifferentiation(t *testing.T) {
	contract := ContractHash([]byte("company-founding-doc-v1"))

	wardex := NewUIDZeroFromContract(contract, "wardex", false)
	ransom := NewUIDZeroFromContract(contract, "anti-ransomware", false)

	if wardex.ID() == ransom.ID() {
		t.Fatal("different salts should produce different RootIDs")
	}
	if bytes.Equal(wardex.PublicKey, ransom.PublicKey) {
		t.Fatal("different salts should produce different keypairs")
	}
}

func TestUIDZeroFromContractDifferentContract(t *testing.T) {
	c1 := ContractHash([]byte("contract-A"))
	c2 := ContractHash([]byte("contract-B"))

	a := NewUIDZeroFromContract(c1, "wardex", false)
	b := NewUIDZeroFromContract(c2, "wardex", false)

	if a.ID() == b.ID() {
		t.Fatal("different contracts should produce different identities")
	}
}

func TestRandomUIDZeroHasNoContract(t *testing.T) {
	uid := NewUIDZero("random-seed", true)
	if uid.ContractOf() != nil {
		t.Fatal("random UID0 should not be contract-bound")
	}
}
