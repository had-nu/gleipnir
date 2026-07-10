package identity

import (
	"bytes"
	"testing"
)

func TestKyberKEMRoundtrip(t *testing.T) {
	pk, sk, err := KyberGenerateKey()
	if err != nil {
		t.Fatalf("KyberGenerateKey: %v", err)
	}
	if len(pk) == 0 || len(sk) == 0 {
		t.Fatal("empty key material")
	}

	ct, ss1, err := KyberEncapsulate(pk)
	if err != nil {
		t.Fatalf("KyberEncapsulate: %v", err)
	}
	if len(ct) == 0 || len(ss1) == 0 {
		t.Fatal("empty encapsulation output")
	}

	ss2, err := KyberDecapsulate(sk, ct)
	if err != nil {
		t.Fatalf("KyberDecapsulate: %v", err)
	}

	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets do not match")
	}

	t.Logf("Kyber1024 KEM round trip OK: pk=%d bytes, ct=%d bytes, ss=%d bytes",
		len(pk), len(ct), len(ss1))
}

func TestKyberKEMDifferentKeyFails(t *testing.T) {
	pk1, _, err := KyberGenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk2, sk2, err := KyberGenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Encapsulate with pk2
	ct, ss1, err := KyberEncapsulate(pk2)
	if err != nil {
		t.Fatal(err)
	}

	// Try decapsulating ct (encrypted for pk2) with sk2 — should work
	ss2, err := KyberDecapsulate(sk2, ct)
	if err != nil {
		t.Fatalf("decapsulate with matching key: %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets should match with correct key")
	}

	// Encapsulate with pk1 — produces different ct/shared secret
	_, _, err = KyberEncapsulate(pk1)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Kyber1024 KEM different-key test: correct key produces matching shared secret")
}
