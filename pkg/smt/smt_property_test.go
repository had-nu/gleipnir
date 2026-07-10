package smt

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// GLP-T-A02 — SMT tamper detection, property-based.
// Generate random key/value pairs, insert, prove, flip a single random bit
// in the proof or value, assert Verify() rejects 100% of mutations.
func TestSMTTamperDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}

	const iterations = 10000
	const maxSetSize = 20

	for i := 0; i < iterations; i++ {
		tree := New(256)

		// Generate random key/value set
		n := int(randInt(maxSetSize-1)) + 2 // 2..20 entries
		keys := make([][]byte, n)
		vals := make([][]byte, n)
		for j := 0; j < n; j++ {
			keys[j] = randBytes(32)
			vals[j] = randBytes(32)
			tree.Insert(keys[j], vals[j])
		}

		// Pick a random entry, get its proof
		targetIdx := int(randInt(uint64(n - 1)))
		proof, err := tree.Prove(keys[targetIdx])
		if err != nil {
			t.Fatal(err)
		}

		root := tree.Root()

		// Verify the original proof passes
		if !tree.Verify(keys[targetIdx], vals[targetIdx], root, proof) {
			t.Fatal("original valid proof failed verification")
		}

		// Mutate: flip a single bit in the proof or value
		mutatedValue := make([]byte, len(vals[targetIdx]))
		copy(mutatedValue, vals[targetIdx])
		flipBit(mutatedValue)

		if tree.Verify(keys[targetIdx], mutatedValue, root, proof) {
			t.Fatal("Verify accepted mutated value — single-bit-flip should be rejected")
		}

		// Mutate a random proof chunk
		if len(proof) > 0 {
			mutatedProof := copyProof(proof)
			mutateProofChunk(mutatedProof)

			if tree.Verify(keys[targetIdx], vals[targetIdx], root, mutatedProof) {
				t.Fatal("Verify accepted mutated proof — single-bit-flip should be rejected")
			}
		}

		// Mutate the root
		mutatedRoot := root
		mutatedRoot[0] ^= 1
		if tree.Verify(keys[targetIdx], vals[targetIdx], mutatedRoot, proof) {
			t.Fatal("Verify accepted mutated root — single-bit-flip should be rejected")
		}
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randInt(max uint64) uint64 {
	n, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(max+1))
	return n.Uint64()
}

func flipBit(b []byte) {
	if len(b) == 0 {
		return
	}
	byteIdx := int(randInt(uint64(len(b) - 1)))
	bitIdx := uint(randInt(7))
	b[byteIdx] ^= 1 << bitIdx
}

func copyProof(p [][32]byte) [][32]byte {
	c := make([][32]byte, len(p))
	copy(c, p)
	return c
}

func mutateProofChunk(p [][32]byte) {
	if len(p) == 0 {
		return
	}
	idx := int(randInt(uint64(len(p) - 1)))
	byteOff := int(randInt(31))
	bitOff := uint(randInt(7))
	p[idx][byteOff] ^= 1 << bitOff
}
