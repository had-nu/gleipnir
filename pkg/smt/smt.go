package smt

import (
	"bytes"
	"errors"

	"lukechampine.com/blake3"
)

var ErrNotFound = errors.New("smt: key not found")
var ErrInvalidProof = errors.New("smt: invalid proof")

const hashLen = 32

type SparseMerkleTree struct {
	root     [hashLen]byte
	leafBits int
	store    map[[hashLen]byte]*node
}

type node struct {
	left  [hashLen]byte
	right [hashLen]byte
	hash  [hashLen]byte
	leaf  bool
	key   []byte
	value []byte
}

func New(leafBits int) *SparseMerkleTree {
	return &SparseMerkleTree{
		leafBits: leafBits,
		store:    make(map[[hashLen]byte]*node),
	}
}

func parentHash(left, right [hashLen]byte) [hashLen]byte {
	h := blake3.New(32, nil)
	h.Write(left[:])
	h.Write(right[:])
	var sum [hashLen]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func (smt *SparseMerkleTree) Insert(key []byte, value []byte) error {
	h := blake3.Sum256(value)

	if len(smt.store) == 0 {
		n := &node{
			leaf:  true,
			key:   key,
			value: value,
			hash:  h,
		}
		smt.store[n.hash] = n
		smt.root = n.hash
		return nil
	}

	n := smt.store[smt.root]
	if n == nil {
		n = &node{hash: smt.root}
		smt.store[n.hash] = n
	}

	newRoot := smt.insert(smt.root, key, value, h, smt.leafBits-1)
	smt.root = newRoot
	return nil
}

func (smt *SparseMerkleTree) insert(current [hashLen]byte, key []byte, value []byte, leafHash [hashLen]byte, depth int) [hashLen]byte {
	n, exists := smt.store[current]
	if !exists {
		h := parentHash(current, leafHash)
		nn := &node{left: current, right: leafHash, hash: h}
		smt.store[h] = nn
		return h
	}

	if n.leaf {
		if bytes.Equal(n.key, key) {
			n.value = value
			n.hash = leafHash
			return n.hash
		}

		side := (bitAt(n.key, depth) << 1) | bitAt(key, depth)
		var left, right [hashLen]byte
		switch side {
		case 0:
			left = n.hash
			right = leafHash
		case 1:
			left = n.hash
			right = leafHash
		case 2:
			left = leafHash
			right = n.hash
		case 3:
			left = leafHash
			right = n.hash
		}
		h := parentHash(left, right)
		smt.store[h] = &node{left: left, right: right, hash: h}
		return h
	}

	side := bitAt(key, depth)
	var left, right [hashLen]byte

	if side == 0 {
		left = smt.insert(n.left, key, value, leafHash, depth-1)
		right = n.right
	} else {
		left = n.left
		right = smt.insert(n.right, key, value, leafHash, depth-1)
	}

	h := parentHash(left, right)
	smt.store[h] = &node{left: left, right: right, hash: h}
	return h
}

func (smt *SparseMerkleTree) Root() [hashLen]byte {
	return smt.root
}

func (smt *SparseMerkleTree) Prove(key []byte) ([][hashLen]byte, error) {
	var proof [][hashLen]byte

	current := smt.root
	depth := smt.leafBits - 1

	for depth >= 0 {
		n, exists := smt.store[current]
		if !exists {
			return nil, ErrNotFound
		}

		if n.leaf {
			if bytes.Equal(n.key, key) {
				return proof, nil
			}
			return nil, ErrNotFound
		}

		side := bitAt(key, depth)
		if side == 0 {
			proof = append(proof, n.right)
			current = n.left
		} else {
			proof = append(proof, n.left)
			current = n.right
		}
		depth--
	}

	return nil, ErrNotFound
}

func (smt *SparseMerkleTree) Verify(key []byte, value []byte, root [hashLen]byte, proof [][hashLen]byte) bool {
	leafHash := blake3.Sum256(value)
	current := leafHash

	for i := 0; i < len(proof); i++ {
		side := bitAt(key, smt.leafBits-1-i)
		if side == 0 {
			current = parentHash(current, proof[i])
		} else {
			current = parentHash(proof[i], current)
		}
	}

	return current == root
}

func bitAt(data []byte, bit int) int {
	byteIdx := bit / 8
	if byteIdx >= len(data) {
		return 0
	}
	return int((data[byteIdx] >> (bit % 8)) & 1)
}

func (smt *SparseMerkleTree) Get(key []byte) ([]byte, error) {
	current := smt.root
	depth := smt.leafBits - 1

	for depth >= 0 {
		n, exists := smt.store[current]
		if !exists {
			return nil, ErrNotFound
		}
		if n.leaf {
			if bytes.Equal(n.key, key) {
				return n.value, nil
			}
			return nil, ErrNotFound
		}
		side := bitAt(key, depth)
		if side == 0 {
			current = n.left
		} else {
			current = n.right
		}
		depth--
	}

	return nil, ErrNotFound
}

func (smt *SparseMerkleTree) BulkInsert(entries map[string][]byte) error {
	for key, value := range entries {
		if err := smt.Insert([]byte(key), value); err != nil {
			return err
		}
	}
	return nil
}
