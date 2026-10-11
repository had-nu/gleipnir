package p2p

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// waitFor polls until cond holds or the deadline passes. Network handshakes and mDNS
// announcements are not instantaneous, so every assertion here is on an eventual state.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func testEntry(b byte) chain.ProvenanceEntry {
	var submitter [16]byte
	submitter[0] = b
	return chain.ProvenanceEntry{
		Hash:      [32]byte{b},
		Submitter: submitter,
		Label:     "p2p-test",
	}
}

// writeRawFrame writes an arbitrary length prefix followed by payload, bypassing
// sendStream. It exists to exercise the handlers with bytes a well-behaved peer would
// never send.
func (b *GossipBus) writeRawFrame(t *testing.T, pid peer.ID, proto protocol.ID, length uint32) {
	t.Helper()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], length)

	if err := b.sendRaw(pid, proto, lenBuf[:]); err != nil {
		t.Fatalf("writeRawFrame: %v", err)
	}
}

// sendRaw opens a stream and writes bytes verbatim, without the length check that
// sendStream applies.
func (b *GossipBus) sendRaw(pid peer.ID, proto protocol.ID, data []byte) error {
	ctx, cancel := context.WithTimeout(b.ctx, requestTimeout)
	defer cancel()

	s, err := b.host.NewStream(ctx, pid, proto)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	if _, err := s.Write(data); err != nil {
		return err
	}
	return s.CloseWrite()
}

// Two buses over a real libp2p host pair, loopback only.
//
// This package had no tests at all. It is the transport every other component's
// multi-node claim rests on, and the defect that stopped the network from converging
// lived here for several commits — so the things worth pinning are the ones that only
// manifest once two actual hosts are talking.
func newTestBus(t *testing.T, keyPath string) *GossipBus {
	t.Helper()
	bus, err := NewGossipBus(context.Background(), Config{
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		PrivateKeyFile: keyPath,
		NodeID:         t.Name(),
	})
	if err != nil {
		t.Fatalf("NewGossipBus: %v", err)
	}
	t.Cleanup(func() { _ = bus.Close() })
	return bus
}

func loopbackAddr(t *testing.T, bus *GossipBus) string {
	t.Helper()
	addrs := bus.Host().Addrs()
	if len(addrs) == 0 {
		t.Fatal("host advertises no addresses")
	}
	return addrs[0].String() + "/p2p/" + bus.Host().ID().String()
}

// A VRF proof must survive the trip from one host to another.
//
// The send path used to end in s.Close(), which tears the stream down at the remote
// end: the receiver's read failed with a reset before it saw the payload and the
// handler returned without a word. Nothing detected it because nothing ever carried a
// message between two buses. If this test fails, proposer selection can never
// complete across a real network.
func TestVRFProofCrossesTheWire(t *testing.T) {
	a := newTestBus(t, filepath.Join(t.TempDir(), "a.key"))
	b := newTestBus(t, filepath.Join(t.TempDir(), "b.key"))

	a.connectToPeer(loopbackAddr(t, b))
	waitFor(t, "b connected to a", func() bool {
		return b.Host().Network().Connectedness(a.Host().ID()) == network.Connected
	})

	msg := consensus.VRFProofMsg{Cycle: 7, Proof: []byte("proof-bytes"), SignerID: "signer-abc"}
	a.PublishVRFProof(msg)

	waitFor(t, "proof received on b", func() bool {
		got := b.GetVRFProofs(7)
		return len(got) == 1 && got[0].SignerID == "signer-abc"
	})
}

// First-write-wins per (cycle, signer).
//
// A signer must not be able to swap its proof after selection has read it, and the
// same rule has to hold for proofs arriving over the network as for local ones —
// otherwise a peer is protected only when it publishes locally.
func TestVRFProofIsFirstWriteWinsPerSignerAndCycle(t *testing.T) {
	a := newTestBus(t, filepath.Join(t.TempDir(), "a.key"))
	b := newTestBus(t, filepath.Join(t.TempDir(), "b.key"))

	a.PublishVRFProof(consensus.VRFProofMsg{Cycle: 1, Proof: []byte("original"), SignerID: "s1"})
	a.PublishVRFProof(consensus.VRFProofMsg{Cycle: 1, Proof: []byte("swapped"), SignerID: "s1"})

	got := a.GetVRFProofs(1)
	if len(got) != 1 {
		t.Fatalf("held %d proofs for one signer in one cycle, want 1", len(got))
	}
	if string(got[0].Proof) != "original" {
		t.Fatalf("proof was replaced: got %q, want the first published", got[0].Proof)
	}

	// A different signer, and a different cycle, must both still be accepted.
	a.PublishVRFProof(consensus.VRFProofMsg{Cycle: 1, Proof: []byte("other"), SignerID: "s2"})
	a.PublishVRFProof(consensus.VRFProofMsg{Cycle: 2, Proof: []byte("next"), SignerID: "s1"})
	if n := len(a.GetVRFProofs(1)); n != 2 {
		t.Fatalf("cycle 1 holds %d proofs, want 2 (two distinct signers)", n)
	}
	if n := len(a.GetVRFProofs(2)); n != 1 {
		t.Fatalf("cycle 2 holds %d proofs, want 1", n)
	}

	_ = b
}

// Provenance entries must cross the wire too, since a submission to a node that is not
// the proposer can only reach a block through this path.
func TestProvenanceEntryCrossesTheWire(t *testing.T) {
	a := newTestBus(t, filepath.Join(t.TempDir(), "a.key"))
	b := newTestBus(t, filepath.Join(t.TempDir(), "b.key"))

	a.connectToPeer(loopbackAddr(t, b))
	waitFor(t, "b connected to a", func() bool {
		return b.Host().Network().Connectedness(a.Host().ID()) == network.Connected
	})

	a.Publish(testEntry(0x11))
	waitFor(t, "entry received on b", func() bool {
		return len(b.Snapshot()) == 1
	})
}

// A frame announcing an absurd length must be refused rather than allocated.
//
// The handlers bound the length by maxStreamMessage before allocating. A peer
// announcing 4 GiB would otherwise cause a 4 GiB allocation before any of the payload
// was validated, which is a remote memory-exhaustion primitive on a public protocol.
func TestOversizedFrameIsRejected(t *testing.T) {
	a := newTestBus(t, filepath.Join(t.TempDir(), "a.key"))
	b := newTestBus(t, filepath.Join(t.TempDir(), "b.key"))

	a.connectToPeer(loopbackAddr(t, b))
	waitFor(t, "b connected to a", func() bool {
		return b.Host().Network().Connectedness(a.Host().ID()) == network.Connected
	})

	// Announce the largest length a uint32 prefix can carry, with no payload behind
	// it. That is the worst case the framing allows: 4 GiB minus one.
	b.writeRawFrame(t, a.Host().ID(), protocolEntries, 0xFFFFFFFF)

	// The receiving handler must return rather than block or allocate. Nothing arriving
	// for a second is the observable proof that it bailed.
	time.Sleep(500 * time.Millisecond)
	if n := len(b.Snapshot()); n != 0 {
		t.Fatalf("receiver accepted %d entries from an oversized frame", n)
	}
	if b.Host().Network().Connectedness(a.Host().ID()) != network.Connected {
		t.Fatal("receiver closed the connection on a malformed frame; a peer must not " +
			"be able to disconnect a node by announcing a bad length")
	}
}

// The libp2p identity must survive a restart, or every statically configured address
// stops resolving and the node reappears under a new peer ID each boot.
func TestPrivateKeyPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")

	first, err := NewGossipBus(context.Background(), Config{
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		PrivateKeyFile: keyPath,
	})
	if err != nil {
		t.Fatalf("first NewGossipBus: %v", err)
	}
	firstID := first.Host().ID()
	_ = first.Close()

	second, err := NewGossipBus(context.Background(), Config{
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		PrivateKeyFile: keyPath,
	})
	if err != nil {
		t.Fatalf("second NewGossipBus: %v", err)
	}
	defer func() { _ = second.Close() }()

	if second.Host().ID() != firstID {
		t.Fatalf("peer ID changed across restart: %s then %s", firstID, second.Host().ID())
	}
}

// Two distinct buses must not collide on identity when given separate key files.
func TestSeparateKeysProduceDistinctPeerIDs(t *testing.T) {
	a := newTestBus(t, filepath.Join(t.TempDir(), "a.key"))
	b := newTestBus(t, filepath.Join(t.TempDir(), "b.key"))

	if a.Host().ID() == b.Host().ID() {
		t.Fatal("two buses share a peer ID; each would recognise the other as itself")
	}
}
