package identity

import (
	"crypto/rand"
	"fmt"
)

// GenerateLivenessNonce creates a CSPRNG nonce for the liveness challenge.
func GenerateLivenessNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	return nonce, nil
}
