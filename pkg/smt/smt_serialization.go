package smt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// MarshalJSON implements json.Marshaler for SparseMerkleTree.
func (t *SparseMerkleTree) MarshalJSON() ([]byte, error) {
	type serializableNode struct {
		Left  [hashLen]byte `json:"left"`
		Right [hashLen]byte `json:"right"`
		Hash  [hashLen]byte `json:"hash"`
		Leaf  bool          `json:"leaf"`
		Key   []byte        `json:"key,omitempty"`
		Value []byte        `json:"value,omitempty"`
	}

	type serializableTree struct {
		Root   [hashLen]byte          `json:"root"`
		Depth  int                    `json:"depth"`
		Zeroes [][hashLen]byte        `json:"zeroes"`
		Store  map[string]serializableNode `json:"store"`
	}

	st := serializableTree{
		Root:   t.root,
		Depth:  t.depth,
		Zeroes: t.zeroes,
		Store:  make(map[string]serializableNode, len(t.store)),
	}

	for k, v := range t.store {
		keyStr := hex.EncodeToString(k[:])
		st.Store[keyStr] = serializableNode{
			Left:  v.left,
			Right: v.right,
			Hash:  v.hash,
			Leaf:  v.leaf,
			Key:   v.key,
			Value: v.value,
		}
	}

	return json.Marshal(st)
}

// UnmarshalJSON implements json.Unmarshaler for SparseMerkleTree.
func (t *SparseMerkleTree) UnmarshalJSON(data []byte) error {
	type serializableNode struct {
		Left  [hashLen]byte `json:"left"`
		Right [hashLen]byte `json:"right"`
		Hash  [hashLen]byte `json:"hash"`
		Leaf  bool          `json:"leaf"`
		Key   []byte        `json:"key,omitempty"`
		Value []byte        `json:"value,omitempty"`
	}

	type serializableTree struct {
		Root   [hashLen]byte                `json:"root"`
		Depth  int                          `json:"depth"`
		Zeroes [][hashLen]byte              `json:"zeroes"`
		Store  map[string]serializableNode  `json:"store"`
	}

	var st serializableTree
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}

	t.root = st.Root
	t.depth = st.Depth
	t.zeroes = st.Zeroes
	t.store = make(map[[hashLen]byte]*node, len(st.Store))

	for kStr, v := range st.Store {
		kBytes, err := hex.DecodeString(kStr)
		if err != nil {
			return fmt.Errorf("decode store key: %w", err)
		}
		var k [hashLen]byte
		copy(k[:], kBytes)
		t.store[k] = &node{
			left:  v.Left,
			right: v.Right,
			hash:  v.Hash,
			leaf:  v.Leaf,
			key:   v.Key,
			value: v.Value,
		}
	}

	return nil
}