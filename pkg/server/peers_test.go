package server

import (
	"strings"
	"sync"
	"testing"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func peerUID(t *testing.T, entropy string) *identity.UIDZeroSoulbound {
	t.Helper()
	var networkID [32]byte
	copy(networkID[:], []byte("gleipnir-test-network"))
	uid, err := identity.NewUIDZero(entropy, networkID, true)
	if err != nil {
		t.Fatalf("NewUIDZero: %v", err)
	}
	return uid
}

// recordingBus is a GossipChannel that records the VRF proofs published through it.
//
// The interface is embedded so that any method the engine calls which is not
// overridden here panics rather than silently succeeding against a nil interface.
// A stub that answers everything with a zero value is the same defect the VRF
// Verify method was.
type recordingBus struct {
	consensus.GossipChannel

	mu      sync.Mutex
	cycles  []uint64
	signers []string
}

func (b *recordingBus) Publish(chain.ProvenanceEntry)               {}
func (b *recordingBus) Snapshot() []chain.ProvenanceEntry           { return nil }
func (b *recordingBus) RemoveEntries(map[[32]byte]bool)             {}
func (b *recordingBus) Propose(chain.Block, string)                 {}
func (b *recordingBus) GetProposed(uint64) *chain.Block             { return nil }
func (b *recordingBus) PublishFinal(chain.Block, string)            {}
func (b *recordingBus) GetFinal(uint64) *chain.Block                { return nil }
func (b *recordingBus) PublishSig(consensus.BlockSig)               {}
func (b *recordingBus) GetSigs(uint64) []consensus.BlockSig         { return nil }
func (b *recordingBus) GetVRFProofs(uint64) []consensus.VRFProofMsg { return nil }

func (b *recordingBus) PublishVRFProof(p consensus.VRFProofMsg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cycles = append(b.cycles, p.Cycle)
	b.signers = append(b.signers, p.SignerID)
}

func (b *recordingBus) published() []uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]uint64(nil), b.cycles...)
}

// A peer set with no transport must be refused. This is the configuration that used
// to be accepted and then ignored: the node believed it was one of N validators,
// derived a quorum from N, and could never reach a single peer.
func TestNewServerRejectsPeersWithoutGossip(t *testing.T) {
	uid := peerUID(t, "node-one-entropy-of-sufficient-length")
	peers := []consensus.Peer{
		{UID: *uid, Addr: "val-1", Alive: true},
		{UID: *peerUID(t, "node-two-entropy-of-sufficient-length"), Addr: "val-2", Alive: true},
	}

	_, err := NewServer("val-1", uid,
		WithAllowSimulatedIdentities(true),
		WithPeers(peers),
	)
	if err == nil {
		t.Fatal("a peer set with no gossip transport was accepted")
	}
	if !strings.Contains(err.Error(), "no gossip transport") {
		t.Fatalf("error %q does not name the cause", err)
	}
}

// The mirror case: a transport with nobody to talk to is equally a configuration
// that cannot be satisfied.
func TestNewServerRejectsGossipWithoutPeers(t *testing.T) {
	uid := peerUID(t, "node-one-entropy-of-sufficient-length")

	_, err := NewServer("val-1", uid,
		WithAllowSimulatedIdentities(true),
		WithGossip(&recordingBus{}),
	)
	if err == nil {
		t.Fatal("a gossip transport with no peers was accepted")
	}
	if !strings.Contains(err.Error(), "no peers") {
		t.Fatalf("error %q does not name the cause", err)
	}
}

// The regression. WithPeers must reach the engine, and the engine must then gossip
// VRF proofs through the configured transport. Before this fix the peer list was
// dropped on the floor, the engine was built single-node, and e.gossip stayed nil —
// so the engine's own `if e.gossip == nil` branch took proposer selection down to a
// one-peer list on every deployment.
func TestWithPeersWiresEngineToTransport(t *testing.T) {
	self := peerUID(t, "node-one-entropy-of-sufficient-length")
	peers := []consensus.Peer{
		{UID: *self, Addr: "val-1", Alive: true},
		{UID: *peerUID(t, "node-two-entropy-of-sufficient-length"), Addr: "val-2", Alive: true},
	}
	bus := &recordingBus{}

	srv, err := NewServer("val-1", self,
		WithAllowSimulatedIdentities(true),
		WithPeers(peers),
		WithGossip(bus),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Stop)

	if got := len(srv.Engine().ValidatorSetSnapshot()); got != 2 {
		t.Fatalf("engine sees %d validators, want 2", got)
	}

	// Run one VRF phase and require that a proof actually reached the transport.
	if _, err := srv.Engine().RunVRFPhase(1); err != nil {
		t.Fatalf("RunVRFPhase: %v", err)
	}
	if len(bus.published()) == 0 {
		t.Fatal("no VRF proof was published to the configured transport; the engine is " +
			"not using it")
	}
}

// Single-node remains the default and must not need a transport.
func TestSingleNodeNeedsNoTransport(t *testing.T) {
	uid := peerUID(t, "node-one-entropy-of-sufficient-length")

	srv, err := NewServer("val-1", uid, WithAllowSimulatedIdentities(true))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Stop)

	if got := len(srv.Engine().ValidatorSetSnapshot()); got != 1 {
		t.Fatalf("single-node engine reports %d validators, want 1", got)
	}
}
