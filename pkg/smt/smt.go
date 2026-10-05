package smt

import (
	"bytes"
	"encoding/binary"
	"errors"

	"lukechampine.com/blake3"
)

var ErrNotFound = errors.New("smt: key not found")

const hashLen = 32

type node struct {
	Left  [hashLen]byte `json:"left"`
	Right [hashLen]byte `json:"right"`
	Hash  [hashLen]byte `json:"hash"`
	Leaf  bool          `json:"leaf"`
	Key   []byte        `json:"key"`
	Value []byte        `json:"value"`
}

type SparseMerkleTree struct {
	root   [hashLen]byte
	depth  int
	store  map[[hashLen]byte]*node
	zeroes [][hashLen]byte
}

func New(depth int) *SparseMerkleTree {
	t := &SparseMerkleTree{
		depth:  depth,
		store:  make(map[[hashLen]byte]*node),
		zeroes: make([][hashLen]byte, depth+1),
	}
	for i := 0; i < depth; i++ {
		if i == 0 {
			t.zeroes[i] = [hashLen]byte{}
		} else {
			t.zeroes[i] = parentHash(t.zeroes[i-1], t.zeroes[i-1])
		}
	}
	return t
}

func parentHash(left, right [hashLen]byte) [hashLen]byte {
	h := blake3.New(32, nil)
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	var sum [hashLen]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// leafHash hashes a (key, value) pair into a leaf.
//
// The two lengths are written explicitly before the fields. Without them the
// concatenation is ambiguous: leafHash([]byte("ab"), []byte("c")) and
// leafHash([]byte("a"), []byte("bc")) hash the same 68 bytes to the same digest,
// so a second preimage differing only in where the key ends is trivial to
// construct. Both fields are variable-length here (BulkInsert takes
// map[string][]byte), so this is reachable rather than theoretical.
//
// Lengths are big-endian fixed-width, which makes the encoding injective and
// self-delimiting.
func leafHash(key, value []byte) [hashLen]byte {
	h := blake3.New(32, nil)
	_, _ = h.Write([]byte("leaf"))

	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(key)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(key)

	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(value)

	var sum [hashLen]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func path(key []byte, depth int) uint {
	if depth < 0 {
		return 0
	}
	byteIdx := depth / 8
	if byteIdx >= len(key) {
		return 0
	}
	return uint((key[byteIdx] >> (depth % 8)) & 1)
}

func (t *SparseMerkleTree) Insert(key []byte, value []byte) error {
	t.root = t.insertAt(t.root, key, value, t.depth-1)
	return nil
}

func (t *SparseMerkleTree) insertAt(current [hashLen]byte, key []byte, value []byte, depth int) [hashLen]byte {
	n, exists := t.store[current]

	if !exists {
		lh := leafHash(key, value)
		t.store[lh] = &node{Leaf: true, Key: key, Value: value, Hash: lh}
		return lh
	}

	if n.Leaf {
		if bytes.Equal(n.Key, key) {
			lh := leafHash(key, value)
			t.store[lh] = &node{Leaf: true, Key: key, Value: value, Hash: lh}
			return lh
		}

		if depth < 0 {
			return n.Hash
		}

		existingLH := leafHash(n.Key, n.Value)
		newLH := leafHash(key, value)
		t.store[newLH] = &node{Leaf: true, Key: key, Value: value, Hash: newLH}
		return t.splitAndInsert(n.Key, existingLH, key, newLH, depth)
	}

	b := path(key, depth)
	if b == 0 {
		newLeft := t.insertAt(n.Left, key, value, depth-1)
		newRight := n.Right
		h := parentHash(newLeft, newRight)
		t.store[h] = &node{Left: newLeft, Right: newRight, Hash: h}
		return h
	} else {
		newLeft := n.Left
		newRight := t.insertAt(n.Right, key, value, depth-1)
		h := parentHash(newLeft, newRight)
		t.store[h] = &node{Left: newLeft, Right: newRight, Hash: h}
		return h
	}
}

func (t *SparseMerkleTree) splitAndInsert(key1 []byte, h1 [hashLen]byte, key2 []byte, h2 [hashLen]byte, depth int) [hashLen]byte {
	if depth < 0 {
		return h2
	}

	b1 := path(key1, depth)
	b2 := path(key2, depth)

	if b1 == b2 {
		child := t.splitAndInsert(key1, h1, key2, h2, depth-1)
		zero := t.zeroes[depth]
		if b1 == 0 {
			h := parentHash(child, zero)
			t.store[h] = &node{Left: child, Right: zero, Hash: h}
			return h
		} else {
			h := parentHash(zero, child)
			t.store[h] = &node{Left: zero, Right: child, Hash: h}
			return h
		}
	}

	if b1 == 0 {
		h := parentHash(h1, h2)
		t.store[h] = &node{Left: h1, Right: h2, Hash: h}
		return h
	} else {
		h := parentHash(h2, h1)
		t.store[h] = &node{Left: h2, Right: h1, Hash: h}
		return h
	}
}

func (t *SparseMerkleTree) Root() [hashLen]byte {
	return t.root
}

func (t *SparseMerkleTree) Get(key []byte) ([]byte, error) {
	current := t.root
	depth := t.depth - 1

	for depth >= 0 {
		n, exists := t.store[current]
		if !exists {
			return nil, ErrNotFound
		}
		if n.Leaf {
			if bytes.Equal(n.Key, key) {
				return n.Value, nil
			}
			return nil, ErrNotFound
		}
		b := path(key, depth)
		if b == 0 {
			current = n.Left
		} else {
			current = n.Right
		}
		depth--
	}

	return nil, ErrNotFound
}

// Prove returns an authentication path for key.
//
// Reaching a leaf is not sufficient: the leaf found must be the leaf for key.
// The previous version returned the sibling path as soon as any leaf was
// encountered, so Prove reported success for an absent key. Verify then failed
// (it recomputes leafHash(key, value), which differs), but a caller checking only
// the error from Prove would treat a non-membership query as a successful proof.
func (t *SparseMerkleTree) Prove(key []byte) ([][hashLen]byte, error) {
	var proof [][hashLen]byte
	current := t.root
	depth := t.depth - 1

	for depth >= 0 {
		n, exists := t.store[current]
		if !exists {
			return nil, ErrNotFound
		}
		if n.Leaf {
			if !bytes.Equal(n.Key, key) {
				return nil, ErrNotFound
			}
			return proof, nil
		}

		b := path(key, depth)
		if b == 0 {
			proof = append([][hashLen]byte{n.Right}, proof...)
			current = n.Left
		} else {
			proof = append([][hashLen]byte{n.Left}, proof...)
			current = n.Right
		}
		depth--
	}

	n, exists := t.store[current]
	if !exists || !n.Leaf || !bytes.Equal(n.Key, key) {
		return nil, ErrNotFound
	}
	return proof, nil
}

// Verify recomputes the root from a leaf and its authentication path.
//
// A path longer than the tree is rejected outright. Previously baseDepth went
// negative, path() returned 0 for every such depth, and the surplus siblings were
// folded in as if they were all left-hand siblings — which produced a root that
// could be matched by a caller supplying extra path elements, rather than
// detecting that the path does not belong to the tree.
func (t *SparseMerkleTree) Verify(key []byte, value []byte, root [hashLen]byte, proof [][hashLen]byte) bool {
	if len(proof) > t.depth {
		return false
	}

	lh := leafHash(key, value)
	current := lh

	baseDepth := t.depth - 1 - len(proof)
	for i := 0; i < len(proof); i++ {
		depth := baseDepth + i + 1
		b := path(key, depth)
		if b == 0 {
			current = parentHash(current, proof[i])
		} else {
			current = parentHash(proof[i], current)
		}
	}

	return current == root
}

func (t *SparseMerkleTree) BulkInsert(entries map[string][]byte) error {
	for key, value := range entries {
		if err := t.Insert([]byte(key), value); err != nil {
			return err
		}
	}
	return nil
}
