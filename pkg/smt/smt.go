package smt

import (
	"bytes"
	"errors"

	"lukechampine.com/blake3"
)

var ErrNotFound = errors.New("smt: key not found")

const hashLen = 32

type node struct {
	left  [hashLen]byte
	right [hashLen]byte
	hash  [hashLen]byte
	leaf  bool
	key   []byte
	value []byte
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
	h.Write(left[:])
	h.Write(right[:])
	var sum [hashLen]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func leafHash(key, value []byte) [hashLen]byte {
	h := blake3.New(32, nil)
	h.Write([]byte("leaf"))
	h.Write(key)
	h.Write(value)
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
		t.store[lh] = &node{leaf: true, key: key, value: value, hash: lh}
		return lh
	}

	if n.leaf {
		if bytes.Equal(n.key, key) {
			lh := leafHash(key, value)
			t.store[lh] = &node{leaf: true, key: key, value: value, hash: lh}
			return lh
		}

		if depth < 0 {
			return n.hash
		}

		existingLH := leafHash(n.key, n.value)
		newLH := leafHash(key, value)
		t.store[newLH] = &node{leaf: true, key: key, value: value, hash: newLH}
		return t.splitAndInsert(n.key, existingLH, key, newLH, depth)
	}

	b := path(key, depth)
	if b == 0 {
		newLeft := t.insertAt(n.left, key, value, depth-1)
		newRight := n.right
		h := parentHash(newLeft, newRight)
		t.store[h] = &node{left: newLeft, right: newRight, hash: h}
		return h
	} else {
		newLeft := n.left
		newRight := t.insertAt(n.right, key, value, depth-1)
		h := parentHash(newLeft, newRight)
		t.store[h] = &node{left: newLeft, right: newRight, hash: h}
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
			t.store[h] = &node{left: child, right: zero, hash: h}
			return h
		} else {
			h := parentHash(zero, child)
			t.store[h] = &node{left: zero, right: child, hash: h}
			return h
		}
	}

	if b1 == 0 {
		h := parentHash(h1, h2)
		t.store[h] = &node{left: h1, right: h2, hash: h}
		return h
	} else {
		h := parentHash(h2, h1)
		t.store[h] = &node{left: h2, right: h1, hash: h}
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
		if n.leaf {
			if bytes.Equal(n.key, key) {
				return n.value, nil
			}
			return nil, ErrNotFound
		}
		b := path(key, depth)
		if b == 0 {
			current = n.left
		} else {
			current = n.right
		}
		depth--
	}

	return nil, ErrNotFound
}

func (t *SparseMerkleTree) Prove(key []byte) ([][hashLen]byte, error) {
	var proof [][hashLen]byte
	current := t.root
	depth := t.depth - 1

	for depth >= 0 {
		n, exists := t.store[current]
		if !exists {
			return nil, ErrNotFound
		}
		if n.leaf {
			return proof, nil
		}

		b := path(key, depth)
		if b == 0 {
			proof = append([][hashLen]byte{n.right}, proof...)
			current = n.left
		} else {
			proof = append([][hashLen]byte{n.left}, proof...)
			current = n.right
		}
		depth--
	}

	return nil, ErrNotFound
}

func (t *SparseMerkleTree) Verify(key []byte, value []byte, root [hashLen]byte, proof [][hashLen]byte) bool {
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
