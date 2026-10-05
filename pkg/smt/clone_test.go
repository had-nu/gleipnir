package smt

import (
	"bytes"
	"testing"
)

// A snapshot has to be a real copy. Nodes are pointers, so a shallow struct copy
// would share them and the snapshot would mutate underneath the caller -- which is
// exactly what the engine relies on when it restores after a failed cycle.
func TestCloneIsDeep(t *testing.T) {
	tr := New(64)
	if err := tr.Insert([]byte("k1"), []byte("v1")); err != nil {
		t.Fatal(err)
	}

	snap := tr.Clone()
	before := snap.Root()

	if err := tr.Insert([]byte("k2"), []byte("v2")); err != nil {
		t.Fatal(err)
	}

	if snap.Root() == tr.Root() {
		t.Fatal("mutating the original did not change its root; the test is not exercising clone")
	}
	if snap.Root() != before {
		t.Fatalf("snapshot root moved from %x to %x when the original was mutated", before, snap.Root())
	}
	if _, err := snap.Get([]byte("k2")); err == nil {
		t.Fatal("snapshot sees a key inserted into the original after the clone")
	}
}

// The restored tree has to be usable, not just have the right root: the engine keeps
// running cycles on it after a rollback.
func TestCloneRemainsUsable(t *testing.T) {
	tr := New(64)
	if err := tr.Insert([]byte("before"), []byte("1")); err != nil {
		t.Fatal(err)
	}
	snap := tr.Clone()

	// Mutate and roll back.
	if err := tr.Insert([]byte("during-failed-cycle"), []byte("2")); err != nil {
		t.Fatal(err)
	}
	restored := snap

	got, err := restored.Get([]byte("before"))
	if err != nil || string(got) != "1" {
		t.Fatalf("restored tree lost its prior entry: %q %v", got, err)
	}
	if err := restored.Insert([]byte("after-rollback"), []byte("3")); err != nil {
		t.Fatal(err)
	}
	got, err = restored.Get([]byte("after-rollback"))
	if err != nil || string(got) != "3" {
		t.Fatalf("restored tree is not writable: %q %v", got, err)
	}
	if restored.Root() == tr.Root() {
		t.Fatal("restored tree and original converge to the same root, so the clone is shared")
	}
}

// Proofs issued against a clone must verify against that clone's root, and must not
// verify against the original's: the engine verifies a candidate block's StateRoot
// against the tree it holds, so a stale proof leaking across would be accepted.
func TestCloneProofsAreScopedToTheClone(t *testing.T) {
	tr := New(64)
	if err := tr.Insert([]byte("k"), []byte("v")); err != nil {
		t.Fatal(err)
	}
	snap := tr.Clone()

	proof, err := snap.Prove([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Verify([]byte("k"), []byte("v"), snap.Root(), proof) {
		t.Fatal("proof from the clone does not verify against the clone root")
	}
	if err := tr.Insert([]byte("other"), []byte("w")); err != nil {
		t.Fatal(err)
	}
	if tr.Verify([]byte("k"), []byte("v"), tr.Root(), proof) {
		t.Fatal("a clone's proof verified against a different root")
	}
}

// The JSON round-trip used by persistence must agree with Clone, since both are
// restore mechanisms.
func TestCloneMatchesJSONRoundTrip(t *testing.T) {
	tr := New(128)
	for _, kv := range [][2]string{{"a", "1"}, {"b", "2"}, {"c", "3"}} {
		if err := tr.Insert([]byte(kv[0]), []byte(kv[1])); err != nil {
			t.Fatal(err)
		}
	}
	viaClone := tr.Clone()

	data, err := tr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var viaJSON SparseMerkleTree
	if err := viaJSON.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}

	if viaClone.Root() != viaJSON.Root() {
		t.Fatalf("clone root %x != json root %x", viaClone.Root(), viaJSON.Root())
	}
	if !bytes.Equal(viaClone.zeroes[tr.depth-1][:], viaJSON.zeroes[tr.depth-1][:]) {
		t.Fatal("zero-hash chain differs between clone and json round-trip")
	}
	if viaClone.depth != viaJSON.depth {
		t.Fatalf("depth %d != %d", viaClone.depth, viaJSON.depth)
	}
}
