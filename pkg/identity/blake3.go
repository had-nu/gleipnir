package identity

import (
	"lukechampine.com/blake3"
)

// Hash computes the BLAKE3 digest of the combined input data.
func Hash(data ...[]byte) []byte {
	h := blake3.New(32, nil)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// Derive computes a key derivation using BLAKE3 with context.
func Derive(context string, material []byte, length int) []byte {
	out := make([]byte, length)
	blake3.DeriveKey(out, context, material)
	return out
}
