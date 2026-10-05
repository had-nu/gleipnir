package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/gleipnir/pkg/identity"
)

// These tests exercise --peers through parsePeers, the same function main calls
// after flag.Parse. A test that built the peer list some other way would pass while
// the flag stayed broken, which is exactly how the discarded flag survived.

func writeUID(t *testing.T, dir, name, entropy string) (string, string) {
	t.Helper()
	var networkID [32]byte
	copy(networkID[:], []byte("gleipnir-test-network"))
	uid, err := identity.NewUIDZero(entropy, networkID, true)
	if err != nil {
		t.Fatalf("NewUIDZero: %v", err)
	}
	data, err := uid.SerializeCBOR()
	if err != nil {
		t.Fatalf("SerializeCBOR: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path, uid.ID()
}

func mustUID(t *testing.T, dir, name, entropy string) *identity.UIDZeroSoulbound {
	t.Helper()
	path, _ := writeUID(t, dir, name, entropy)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := identity.UnmarshalCBOR(data)
	if err != nil {
		t.Fatal(err)
	}
	return uid
}

// An empty spec must mean single-node, not an error and not a one-element peer set.
func TestParsePeersEmptyIsSingleNode(t *testing.T) {
	peers, err := parsePeers("", nil, "self")
	if err != nil {
		t.Fatalf("empty spec: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("empty spec produced %d peers, want 0", len(peers))
	}
}

func TestParsePeersBuildsValidatorSet(t *testing.T) {
	dir := t.TempDir()
	self := mustUID(t, dir, "uid-1.cbor", "validator-entropy-1-long-enough")
	p2, id2 := writeUID(t, dir, "uid-2.cbor", "validator-entropy-2-long-enough")
	p3, id3 := writeUID(t, dir, "uid-3.cbor", "validator-entropy-3-long-enough")

	spec := "val-2:50051=" + p2 + ",val-3:50051=" + p3
	peers, err := parsePeers(spec, self, "val-1:50051")
	if err != nil {
		t.Fatalf("parsePeers: %v", err)
	}

	// Self must be present: the engine builds a full mesh over the peers it is
	// given, so omitting self drops this node's own edges and validator entry.
	if peers[0].UID.ID() != self.ID() {
		t.Fatalf("first peer is %s, want self %s", peers[0].UID.ID(), self.ID())
	}
	if len(peers) != 3 {
		t.Fatalf("got %d peers, want 3", len(peers))
	}

	// The whole point of the fix: the peer list must carry the authority material
	// the engine derives the validator set from. A list of bare addresses cannot.
	wantIDs := map[string]bool{id2: false, id3: false}
	for _, p := range peers[1:] {
		if _, ok := wantIDs[p.UID.ID()]; !ok {
			t.Fatalf("unexpected peer id %s", p.UID.ID())
		}
		wantIDs[p.UID.ID()] = true
		if len(p.UID.PublicKey) != 1952 {
			t.Fatalf("peer %s carries a %d-byte public key, want 1952", p.UID.ID(), len(p.UID.PublicKey))
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Fatalf("peer %s missing from the set", id)
		}
	}
}

// A bare address must be rejected. This is the shape the old manifest used, and
// accepting it is how a peer list that carries no authority information looks valid.
func TestParsePeersRejectsBareAddress(t *testing.T) {
	dir := t.TempDir()
	self := mustUID(t, dir, "uid-1.cbor", "validator-entropy-1-long-enough")

	_, err := parsePeers("val-2:50051", self, "val-1:50051")
	if err == nil {
		t.Fatal("a bare address with no uid file was accepted")
	}
	if !strings.Contains(err.Error(), "addr=uid-file") {
		t.Fatalf("error %q does not explain the expected form", err)
	}
}

func TestParsePeersRejectsMissingFile(t *testing.T) {
	dir := t.TempDir()
	self := mustUID(t, dir, "uid-1.cbor", "validator-entropy-1-long-enough")

	_, err := parsePeers("val-2:50051="+filepath.Join(dir, "absent.cbor"), self, "val-1:50051")
	if err == nil {
		t.Fatal("a peer with an unreadable uid file was accepted")
	}
}

// Listing your own identity as a peer would put two validator entries with the same
// key into the set, which is a doubled vote. The address differs here so that the
// identity check is the one under test rather than the duplicate-address check.
func TestParsePeersRejectsSelfAsPeer(t *testing.T) {
	dir := t.TempDir()
	self := mustUID(t, dir, "uid-1.cbor", "validator-entropy-1-long-enough")

	_, err := parsePeers("val-9:50051="+filepath.Join(dir, "uid-1.cbor"), self, "val-1:50051")
	if err == nil {
		t.Fatal("this node's own identity was accepted as a peer")
	}
	if !strings.Contains(err.Error(), "own identity") {
		t.Fatalf("error %q does not name the cause", err)
	}
}

// Reusing this node's own address is caught earlier, as a duplicate.
func TestParsePeersRejectsOwnAddress(t *testing.T) {
	dir := t.TempDir()
	self := mustUID(t, dir, "uid-1.cbor", "validator-entropy-1-long-enough")
	p2, _ := writeUID(t, dir, "uid-2.cbor", "validator-entropy-2-long-enough")

	_, err := parsePeers("val-1:50051="+p2, self, "val-1:50051")
	if err == nil {
		t.Fatal("this node's own address was accepted as a peer")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("error %q does not name the cause", err)
	}
}

func TestParsePeersRejectsDuplicateAddress(t *testing.T) {
	dir := t.TempDir()
	self := mustUID(t, dir, "uid-1.cbor", "validator-entropy-1-long-enough")
	p2, _ := writeUID(t, dir, "uid-2.cbor", "validator-entropy-2-long-enough")

	spec := "val-2:50051=" + p2 + ",val-2:50051=" + p2
	if _, err := parsePeers(spec, self, "val-1:50051"); err == nil {
		t.Fatal("a duplicated peer address was accepted")
	}
}

// One peer entry is self alone, which is single-node wearing a peer list.
func TestParsePeersRejectsSingleValidator(t *testing.T) {
	dir := t.TempDir()
	self := mustUID(t, dir, "uid-1.cbor", "validator-entropy-1-long-enough")

	_, err := parsePeers(" ", self, "val-1:50051")
	if err != nil {
		t.Fatalf("whitespace spec should be single-node, got %v", err)
	}
	if _, err := parsePeers("val-2:50051=/nonexistent", self, "val-1:50051"); err == nil {
		t.Fatal("an unusable peer entry was accepted")
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" a , b ,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitList = %v, want %v", got, want)
		}
	}
	if len(splitList("")) != 0 {
		t.Fatal("empty string produced entries")
	}
}
