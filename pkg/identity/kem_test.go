package identity

import (
	"bytes"
	"testing"
)

func TestKyberKEMRoundtrip(t *testing.T) {
	pk, sk, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}
	if len(pk) == 0 || len(sk) == 0 {
		t.Fatal("empty key material")
	}

	ct, ss1, err := Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	// Assert exact sizes, not merely non-emptiness. Both values are byte slices and
	// both are non-empty, so a swapped return order would satisfy a `len() > 0` check
	// while sending the shared secret on the wire instead of the ciphertext.
	if len(ct) != Kyber1024CiphertextSize {
		t.Fatalf("Encapsulate must return the ciphertext first: got %d bytes, want %d",
			len(ct), Kyber1024CiphertextSize)
	}
	if len(ss1) != Kyber1024SharedKeySize {
		t.Fatalf("Encapsulate must return a %d-byte shared secret, got %d",
			Kyber1024SharedKeySize, len(ss1))
	}

	ss2, err := Decapsulate(sk, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets do not match")
	}

	t.Logf("Kyber1024 KEM round trip OK: pk=%d bytes, ct=%d bytes, ss=%d bytes",
		len(pk), len(ct), len(ss1))
}

// TestEncapsulateReturnOrder pins the (ciphertext, sharedSecret, err) ordering.
//
// This exists because the ordering was once the reverse in pkg/transport: the dialer
// read the results as (ct, ss), sent the 32-byte shared secret where the peer expected
// a 1568-byte ciphertext, and deadlocked the transport handshake. Sizes are asserted
// rather than left to a round trip, because both outputs are non-empty byte slices.
func TestEncapsulateReturnOrder(t *testing.T) {
	pk, _, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}

	first, second, err := Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	if len(first) != Kyber1024CiphertextSize {
		t.Errorf("first return value must be the %d-byte ciphertext, got %d",
			Kyber1024CiphertextSize, len(first))
	}
	if len(second) != Kyber1024SharedKeySize {
		t.Errorf("second return value must be the %d-byte shared secret, got %d",
			Kyber1024SharedKeySize, len(second))
	}
}

func TestKyberKEMDifferentKeyFails(t *testing.T) {
	pk1, _, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pk2, sk2, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Encapsulate with pk2
	ct, ss1, err := Encapsulate(pk2)
	if err != nil {
		t.Fatal(err)
	}

	// Try decapsulating ct (encrypted for pk2) with sk2 — should work
	ss2, err := Decapsulate(sk2, ct)
	if err != nil {
		t.Fatalf("decapsulate with matching key: %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets should match with correct key")
	}

	// Encapsulate with pk1 — produces different ct/shared secret
	_, _, err = Encapsulate(pk1)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Kyber1024 KEM different-key test: correct key produces matching shared secret")
}
