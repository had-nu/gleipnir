// IPC identity — Hash function (BLAKE3).
package identity

import (
	"lukechampine.com/blake3"
)

// Hash computes the BLAKE3-256 hash of the input data.
func Hash(data []byte) []byte {
	h := blake3.Sum256(data)
	return h[:]
}

// Blake3Hash computes the BLAKE3-256 hash of the input data and returns a [32]byte array.
func Blake3Hash(data []byte) [32]byte {
	return blake3.Sum256(data)
}