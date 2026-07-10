package identity

import (
	"crypto/rand"
	"testing"
)

// GLP-T-B01 — Dilithium3 key uniqueness under load.
// Generate N identities and assert zero PublicKey collisions.
func TestKeyUniqueness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping key uniqueness test in short mode")
	}

	const n = 10000 // 10k is feasible in CI; spec target is 100k
	seen := make(map[string]bool)

	for i := 0; i < n; i++ {
		pk, _, err := GenerateDilithiumKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key := string(pk)
		if seen[key] {
			t.Fatalf("PublicKey collision at iteration %d — RNG or key generation defect", i)
		}
		seen[key] = true
	}
}
