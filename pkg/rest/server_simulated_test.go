package rest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func simulatedUID(t *testing.T, seed string) *identity.UIDZeroSoulbound {
	t.Helper()
	var networkID [32]byte
	copy(networkID[:], []byte("gleipnir-test-network-id"))
	uid, err := identity.NewUIDZero(seed, networkID, true)
	if err != nil {
		t.Fatalf("NewUIDZero: %v", err)
	}
	return uid
}

func productionUID(t *testing.T) *identity.UIDZeroSoulbound {
	t.Helper()
	var networkID [32]byte
	copy(networkID[:], []byte("gleipnir-test-network-id"))
	uid, err := identity.NewUIDZero("a-production-entropy-source-of-length", networkID, false)
	if err != nil {
		t.Fatalf("NewUIDZero: %v", err)
	}
	return uid
}

func engineFor(t *testing.T, uid *identity.UIDZeroSoulbound) *consensus.Engine {
	t.Helper()
	node := consensus.Node{UID: *uid, Addr: "test-node"}
	eng := consensus.NewEngine(node, 100*time.Millisecond)
	eng.Start()
	t.Cleanup(eng.Stop)
	return eng
}

// A simulated node identity authorises requests purely on signature checks, so one
// must not be accepted by default. Previously NewServer took any identity.
func TestNewServerRejectsSimulatedIdentityByDefault(t *testing.T) {
	uid := simulatedUID(t, "simulated-node-identity-seed")
	eng := engineFor(t, uid)

	if _, err := NewServer(eng, uid); err == nil {
		t.Fatal("NewServer accepted a simulated node identity")
	} else if !strings.Contains(err.Error(), identity.ErrSimulatedIdentity.Error()) {
		t.Fatalf("error %v does not wrap ErrSimulatedIdentity", err)
	}
}

func TestNewServerAcceptsProductionIdentity(t *testing.T) {
	uid := productionUID(t)
	eng := engineFor(t, uid)

	s, err := NewServer(eng, uid)
	if err != nil {
		t.Fatalf("NewServer rejected a production identity: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop() })
}

func TestNewServerAcceptsSimulatedWithExplicitOptIn(t *testing.T) {
	uid := simulatedUID(t, "simulated-node-identity-seed")
	eng := engineFor(t, uid)

	s, err := NewServer(eng, uid, WithAllowSimulatedIdentities(true))
	if err != nil {
		t.Fatalf("NewServer rejected an explicitly permitted simulated identity: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop() })
}

// A simulated identity in the keys directory must not be admitted for request
// authorisation.
func TestKeysDirSkipsSimulatedIdentity(t *testing.T) {
	uid := simulatedUID(t, "simulated-node-identity-seed")
	data, err := cbor.Marshal(uid)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "uid-simulated.cbor"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	node := productionUID(t)
	eng := engineFor(t, node)

	s, err := NewServer(eng, node, WithKeysDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })

	if _, ok := s.keys[uid.ID()]; ok {
		t.Fatal("a simulated identity from the keys directory was admitted")
	}
}

func TestKeysDirSkipsSimulatedIdentityEvenWithOptInOnNodeOnly(t *testing.T) {
	// Opting the node identity in does not silently opt in whatever else is in the
	// keys directory; here both come from the same simulated seed, and the node
	// identity is registered directly rather than through the directory.
	uid := simulatedUID(t, "simulated-node-identity-seed")
	data, err := cbor.Marshal(uid)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "uid-simulated.cbor"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	node := productionUID(t)
	eng := engineFor(t, node)

	s, err := NewServer(eng, node, WithKeysDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })

	if _, ok := s.keys[uid.ID()]; ok {
		t.Fatal("simulated identity admitted from keys dir")
	}
}

// With opt-in on, the keys directory does admit the simulated identity — this is
// the deliberate local-fixture behaviour the option exists for.
func TestKeysDirAdmitsSimulatedWithOptIn(t *testing.T) {
	uid := simulatedUID(t, "simulated-node-identity-seed")
	data, err := cbor.Marshal(uid)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "uid-simulated.cbor"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	node := productionUID(t)
	eng := engineFor(t, node)

	s, err := NewServer(eng, node, WithKeysDir(dir), WithAllowSimulatedIdentities(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })

	if _, ok := s.keys[uid.ID()]; !ok {
		t.Fatal("simulated identity not admitted despite explicit opt-in")
	}
}
