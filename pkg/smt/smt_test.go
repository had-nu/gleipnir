package smt

import (
	"bytes"
	"testing"
)

func TestInsertAndGet(t *testing.T) {
	tree := New(256)
	err := tree.Insert([]byte("key1"), []byte("value1"))
	if err != nil {
		t.Fatal(err)
	}

	v, err := tree.Get([]byte("key1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, []byte("value1")) {
		t.Fatalf("got %x, want value1", v)
	}

	_, err = tree.Get([]byte("nonexistent"))
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRoot(t *testing.T) {
	tree := New(256)
	root0 := tree.Root()

	tree.Insert([]byte("a"), []byte("1"))
	root1 := tree.Root()

	if root0 == root1 {
		t.Fatal("root should change after insert")
	}

	tree.Insert([]byte("b"), []byte("2"))
	root2 := tree.Root()

	if root1 == root2 {
		t.Fatal("root should change after second insert")
	}
}

func TestProveAndVerify(t *testing.T) {
	tree := New(256)
	tree.Insert([]byte("key"), []byte("value"))

	proof, err := tree.Prove([]byte("key"))
	if err != nil {
		t.Fatal(err)
	}

	ok := tree.Verify([]byte("key"), []byte("value"), tree.Root(), proof)
	if !ok {
		t.Fatal("verify should pass")
	}

	ok = tree.Verify([]byte("key"), []byte("wrong"), tree.Root(), proof)
	if ok {
		t.Fatal("verify should fail for wrong value")
	}

	ok = tree.Verify([]byte("other"), []byte("value"), tree.Root(), proof)
	if ok {
		t.Fatal("verify should fail for wrong key")
	}
}

func TestBulkInsert(t *testing.T) {
	tree := New(256)
	entries := map[string][]byte{
		"k1": []byte("v1"),
		"k2": []byte("v2"),
		"k3": []byte("v3"),
	}

	err := tree.BulkInsert(entries)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range entries {
		got, err := tree.Get([]byte(k))
		if err != nil {
			t.Fatalf("get %s: %v", k, err)
		}
		if !bytes.Equal(got, v) {
			t.Fatalf("get %s: got %x, want %x", k, got, v)
		}
	}
}

func TestVerifyFraudProof(t *testing.T) {
	tree := New(256)
	tree.Insert([]byte("alice"), []byte("data-a"))
	tree.Insert([]byte("bob"), []byte("data-b"))

	proofAlice, err := tree.Prove([]byte("alice"))
	if err != nil {
		t.Fatal(err)
	}

	proofBob, err := tree.Prove([]byte("bob"))
	if err != nil {
		t.Fatal(err)
	}

	ok := tree.Verify([]byte("alice"), []byte("data-a"), tree.Root(), proofAlice)
	if !ok {
		t.Fatal("alice proof should verify for alice")
	}

	ok = tree.Verify([]byte("alice"), []byte("data-a"), tree.Root(), proofBob)
	if ok {
		t.Fatal("bob proof should NOT verify for alice — proof-swap fraud must be detected")
	}

	ok = tree.Verify([]byte("bob"), []byte("data-b"), tree.Root(), proofAlice)
	if ok {
		t.Fatal("alice proof should NOT verify for bob — proof-swap fraud must be detected")
	}

	ok = tree.Verify([]byte("alice"), []byte("data-b"), tree.Root(), proofAlice)
	if ok {
		t.Fatal("wrong value should not verify for alice — value-tampering fraud must be detected")
	}
}

func TestUpdateExisting(t *testing.T) {
	tree := New(256)
	tree.Insert([]byte("key"), []byte("old"))
	tree.Insert([]byte("key"), []byte("new"))

	v, err := tree.Get([]byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, []byte("new")) {
		t.Fatalf("got %x, want new", v)
	}
}
