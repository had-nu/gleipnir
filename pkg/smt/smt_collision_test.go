package smt

import "testing"

// leafHash must be injective over (key, value) pairs. Without explicit lengths,
// leafHash("ab", "c") and leafHash("a", "bc") hash identical byte strings.
func TestLeafHashDistinguishesBoundary(t *testing.T) {
	a := leafHash([]byte("ab"), []byte("c"))
	b := leafHash([]byte("a"), []byte("bc"))
	if a == b {
		t.Fatalf("leafHash collision: (\"ab\",\"c\") == (\"a\",\"bc\") = %x", a)
	}
}

func TestLeafHashDistinguishesEmptyComponents(t *testing.T) {
	cases := [][2][]byte{
		{nil, nil},
		{[]byte("k"), nil},
		{nil, []byte("v")},
		{[]byte("kv"), nil},
		{[]byte("k"), []byte("v")},
	}
	seen := make(map[[hashLen]byte][2]string, len(cases))
	for _, c := range cases {
		h := leafHash(c[0], c[1])
		if prev, ok := seen[h]; ok {
			t.Fatalf("collision between (%q,%q) and (%q,%q)", prev[0], prev[1], c[0], c[1])
		}
		seen[h] = [2]string{string(c[0]), string(c[1])}
	}
}

// Prove must report ErrNotFound for an absent key. Returning a sibling path for a
// non-existent leaf told callers a proof existed for a key that was never inserted.
func TestProveRejectsAbsentKey(t *testing.T) {
	tr := New(64)
	if err := tr.Insert([]byte("present"), []byte("value")); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Prove([]byte("present")); err != nil {
		t.Fatalf("Prove failed for an inserted key: %v", err)
	}
	if _, err := tr.Prove([]byte("absent")); err == nil {
		t.Fatal("Prove reported success for a key that was never inserted")
	}
	if _, err := tr.Get([]byte("absent")); err == nil {
		t.Fatal("Get returned a value for an absent key")
	}
}

// Prove and Verify must agree, and a proof must not verify against a different value.
func TestProofRejectsWrongValue(t *testing.T) {
	tr := New(64)
	for _, kv := range [][2]string{{"k1", "v1"}, {"k2", "v2"}, {"k3", "v3"}} {
		if err := tr.Insert([]byte(kv[0]), []byte(kv[1])); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := tr.Prove([]byte("k2"))
	if err != nil {
		t.Fatal(err)
	}
	root := tr.Root()
	if !tr.Verify([]byte("k2"), []byte("v2"), root, proof) {
		t.Fatal("genuine proof failed to verify")
	}
	if tr.Verify([]byte("k2"), []byte("tampered"), root, proof) {
		t.Fatal("proof verified against the wrong value")
	}
	if tr.Verify([]byte("k1"), []byte("v1"), root, proof) {
		t.Fatal("k2's proof verified for k1")
	}
}

// A path longer than the tree must be rejected. Otherwise baseDepth goes negative,
// path() returns 0 throughout, and surplus siblings are folded in as left-hand ones.
func TestVerifyRejectsOverlongProof(t *testing.T) {
	tr := New(8)
	if err := tr.Insert([]byte("k"), []byte("v")); err != nil {
		t.Fatal(err)
	}
	proof, err := tr.Prove([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	root := tr.Root()
	if !tr.Verify([]byte("k"), []byte("v"), root, proof) {
		t.Fatal("baseline proof failed")
	}

	extra := append([][hashLen]byte{}, proof...)
	extra = append(extra, make([][hashLen]byte, 8)...)
	if tr.Verify([]byte("k"), []byte("v"), root, extra) {
		t.Fatal("proof longer than the tree was accepted")
	}
}

// Short keys must not collide: path() reads bit depth%8 of key[depth/8], and
// returns 0 for a depth past the end of the key, so keys of different lengths can
// share a routing path. Retrieval must still distinguish them.
func TestShortKeysRemainRetrievable(t *testing.T) {
	tr := New(64)
	keys := []string{"a", "b", "ab", "k", ""}
	for i, k := range keys {
		v := []byte{byte(i)}
		if err := tr.Insert([]byte(k), v); err != nil {
			t.Fatalf("Insert(%q): %v", k, err)
		}
	}
	for i, k := range keys {
		got, err := tr.Get([]byte(k))
		if err != nil {
			t.Errorf("Get(%q): %v", k, err)
			continue
		}
		if len(got) != 1 || got[0] != byte(i) {
			t.Errorf("Get(%q) = %x, want %02x", k, got, byte(i))
		}
	}
}

// Property: for any pair of distinct entries, proofs must not verify for each other.
func TestProofsAreDistinct(t *testing.T) {
	tr := New(128)
	entries := [][2]string{
		{"alpha", "1"}, {"beta", "2"}, {"gamma", "3"},
		{"", "4"}, {"x", ""}, {"alphabet", "5"},
	}
	for _, e := range entries {
		if err := tr.Insert([]byte(e[0]), []byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	root := tr.Root()
	for _, a := range entries {
		pa, err := tr.Prove([]byte(a[0]))
		if err != nil {
			t.Fatalf("Prove(%q): %v", a[0], err)
		}
		if !tr.Verify([]byte(a[0]), []byte(a[1]), root, pa) {
			t.Fatalf("own proof failed for %q", a[0])
		}
		for _, b := range entries {
			if a == b {
				continue
			}
			if tr.Verify([]byte(b[0]), []byte(b[1]), root, pa) {
				t.Errorf("%q's proof verified for (%q,%q)", a[0], b[0], b[1])
			}
		}
	}
}
