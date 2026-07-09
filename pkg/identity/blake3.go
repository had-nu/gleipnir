// IPC identity — BLAKE3 hash utilities.
package identity

import (
	"lukechampine.com/blake3"
)

func Hash(data ...[]byte) []byte {
	h := blake3.New(32, nil)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func Derive(context string, material []byte, length int) []byte {
	out := make([]byte, length)
	blake3.DeriveKey(out, context, material)
	return out
}
