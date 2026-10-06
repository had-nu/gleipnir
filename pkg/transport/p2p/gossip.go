// libp2p GossipChannel implementation for multi-node consensus.
package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	"github.com/multiformats/go-multiaddr"
)

const (
	protocolEntries   = protocol.ID("/gleipnir/entries/1.0.0")
	protocolProposals = protocol.ID("/gleipnir/proposals/1.0.0")
	protocolSigs      = protocol.ID("/gleipnir/sigs/1.0.0")
	protocolVRFProofs = protocol.ID("/gleipnir/vrfproofs/1.0.0")

	dialTimeout    = 10 * time.Second
	requestTimeout = 30 * time.Second
)

type Config struct {
	ListenAddrs    []string
	BootstrapPeers []string
	EnableMDNS     bool
	MDNSServiceTag string
	PrivateKeyFile string
	NodeID         string
}

type GossipBus struct {
	host      host.Host
	discovery mdns.Service
	notifee   *mdnsNotifee //nolint:unused

	mu        sync.Mutex
	pending   []chain.ProvenanceEntry
	proposals map[uint64]*chain.Block
	finals    map[uint64]*chain.Block
	sigs      map[uint64][]consensus.BlockSig
	vrfProofs map[uint64][]consensus.VRFProofMsg
	connected map[peer.ID]bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup //nolint:unused
}

// Compile-time proof that GossipBus satisfies the interface the engine consumes.
//
// Without this assertion the two missing methods that made this type unusable went
// unnoticed for as long as the package existed: nothing in production constructed a
// GossipBus, so the incompatibility only surfaced if someone wired it up. The
// assertion turns that from a runtime surprise into a build failure.
var _ consensus.GossipChannel = (*GossipBus)(nil)

// mdnsNotifee implements mdns.Notifee
type mdnsNotifee struct {
	bus *GossipBus
}

func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.bus.host.ID() {
		return
	}
	n.bus.mu.Lock()
	already := n.bus.connected[pi.ID]
	n.bus.mu.Unlock()
	if already {
		return
	}
	n.bus.connectToPeerInfo(pi)
}

// loadOrGenerateKey returns the libp2p identity for this node.
//
// With PrivateKeyFile set, the key is read from or created at that path and the
// file is created with 0600 on first use. The key is unmarshalled with
// UnmarshalPrivateKey rather than being regenerated, which is what keeps the peer
// address stable across restarts — the reason PrivateKeyFile exists at all.
func loadOrGenerateKey(path string) (crypto.PrivKey, error) {
	if path == "" {
		privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		return privKey, nil
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		privKey, err := crypto.UnmarshalPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse libp2p key %s: %w", path, err)
		}
		return privKey, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("read libp2p key %s: %w", path, err)
	}

	privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	raw, err := crypto.MarshalPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal libp2p key: %w", err)
	}
	// 0600: the file is the node's transport identity. Anyone who reads it can
	// impersonate this node to its peers.
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, fmt.Errorf("write libp2p key %s: %w", path, err)
	}
	return privKey, nil
}

func NewGossipBus(ctx context.Context, cfg Config) (*GossipBus, error) {
	ctx, cancel := context.WithCancel(ctx)

	// Load or generate the libp2p identity.
	//
	// This is what makes a node's peer address stable across restarts. Generating a
	// fresh key on every boot means the node advertises a different peer ID each time,
	// so a statically configured bootstrap address stops resolving and peers cannot
	// reconnect. The previous version accepted PrivateKeyFile and discarded it.
	privKey, err := loadOrGenerateKey(cfg.PrivateKeyFile)
	if err != nil {
		cancel()
		return nil, err
	}

	ps, err := pstoremem.NewPeerstore()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("peerstore: %w", err)
	}

	listenAddrs := []multiaddr.Multiaddr{}
	for _, a := range cfg.ListenAddrs {
		ma, err := multiaddr.NewMultiaddr(a)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("listen addr %s: %w", a, err)
		}
		listenAddrs = append(listenAddrs, ma)
	}

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(listenAddrs...),
		libp2p.Peerstore(ps),
		libp2p.DisableRelay(),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create host: %w", err)
	}

	notifee := &mdnsNotifee{bus: nil}
	bus := &GossipBus{
		host:      h,
		proposals: make(map[uint64]*chain.Block),
		finals:    make(map[uint64]*chain.Block),
		sigs:      make(map[uint64][]consensus.BlockSig),
		vrfProofs: make(map[uint64][]consensus.VRFProofMsg),
		connected: make(map[peer.ID]bool),
		ctx:       ctx,
		cancel:    cancel,
	}
	notifee.bus = bus

	h.SetStreamHandler(protocolEntries, bus.handleEntriesStream)
	h.SetStreamHandler(protocolProposals, bus.handleProposalsStream)
	h.SetStreamHandler(protocolSigs, bus.handleSigsStream)
	h.SetStreamHandler(protocolVRFProofs, bus.handleVRFProofsStream)

	if cfg.EnableMDNS {
		if cfg.MDNSServiceTag == "" {
			cfg.MDNSServiceTag = "gleipnir"
		}
		s := mdns.NewMdnsService(h, cfg.MDNSServiceTag, notifee)
		bus.discovery = s
		if err := s.Start(); err != nil {
			_ = h.Close()
			cancel()
			return nil, fmt.Errorf("mdns start: %w", err)
		}
	}

	for _, peerAddr := range cfg.BootstrapPeers {
		bus.connectToPeer(peerAddr)
	}

	// Re-dial on a schedule.
	//
	// Nodes in a compose topology start at the same instant, so the first dial
	// attempt to a peer that has not finished listening fails. Without a retry the
	// mesh stays permanently incomplete and asymmetric: each node keeps whichever
	// connections happened to succeed, and a node that nobody dialled receives
	// nothing at all. A gossip protocol cannot tolerate a half-connected graph, so
	// the bootstrap set is retried until every node has dialled every other.
	if len(cfg.BootstrapPeers) > 0 {
		go bus.redialLoop(cfg.BootstrapPeers)
	}

	log.Printf("P2P host started: %s (peers: %d)", h.ID(), len(h.Network().Peers()))
	return bus, nil
}

// redialPeriod is how often the bootstrap set is re-dialled. Short enough that a
// node which missed its window recovers quickly, long enough not to churn streams.
const redialPeriod = 10 * time.Second

// redialRetryInterval is the minimum time between retry attempts for a given peer.
// This prevents a single slow dial from blocking the entire redial loop.
const redialRetryInterval = 2 * time.Second

func (b *GossipBus) redialLoop(addrs []string) {
	ticker := time.NewTicker(redialPeriod)
	defer ticker.Stop()

	// Track the last attempt time per peer ID to avoid hammering a peer that
	// consistently fails to dial (e.g. missing transport addresses).
	lastAttempt := make(map[peer.ID]time.Time)

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			for _, addr := range addrs {
				pi, err := parseAddrInfo(addr)
				if err != nil {
					log.Printf("redial: failed to parse bootstrap addr %s: %v", addr, err)
					continue
				}

				// Throttle: skip this peer if we've attempted it too recently.
				if lastAttempt[pi.ID].Add(redialRetryInterval).After(time.Now()) {
					continue
				}

				if b.host.Network().Connectedness(pi.ID) == network.Connected {
					lastAttempt[pi.ID] = time.Now()
					continue
				}

				log.Printf("redial: dialling peer %s (last attempt: %v ago)", pi.ID, time.Since(lastAttempt[pi.ID]))
				b.connectToPeerInfo(*pi)
				lastAttempt[pi.ID] = time.Now()
			}
		}
	}
}

func parseAddrInfo(addrStr string) (*peer.AddrInfo, error) {
	ma, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		return nil, err
	}
	return peer.AddrInfoFromP2pAddr(ma)
}

func (b *GossipBus) connectToPeer(addrStr string) {
	pi, err := parseAddrInfo(addrStr)
	if err != nil {
		log.Printf("bootstrap addr %s: %v", addrStr, err)
		return
	}
	b.connectToPeerInfo(*pi)
}

func (b *GossipBus) connectToPeerInfo(pi peer.AddrInfo) {
	ctx, cancel := context.WithTimeout(b.ctx, dialTimeout)
	defer cancel()

	if err := b.host.Connect(ctx, pi); err != nil {
		log.Printf("connect to %s: %v", pi.ID, err)
		return
	}
	b.mu.Lock()
	b.connected[pi.ID] = true
	b.mu.Unlock()
	log.Printf("connected to peer %s", pi.ID)
}

// --- GossipChannel interface implementation ---

func (b *GossipBus) Publish(entry chain.ProvenanceEntry) {
	b.mu.Lock()
	b.pending = append(b.pending, entry)
	b.mu.Unlock()
	b.broadcastEntry(entry)
}

func (b *GossipBus) Snapshot() []chain.ProvenanceEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]chain.ProvenanceEntry, len(b.pending))
	copy(out, b.pending)
	return out
}

func (b *GossipBus) RemoveEntries(remove map[[32]byte]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	kept := make([]chain.ProvenanceEntry, 0, len(b.pending))
	for _, e := range b.pending {
		if !remove[e.Hash] {
			kept = append(kept, e)
		}
	}
	b.pending = kept
}

// Propose stores a candidate block for a cycle.
//
// First-write-wins, matching MemoryBus: a proposer must not be able to replace the
// candidate after validators have begun verifying it.
func (b *GossipBus) Propose(block chain.Block, proposerID string) {
	b.mu.Lock()
	_, exists := b.proposals[block.Index]
	if !exists {
		b.proposals[block.Index] = chain.CloneBlock(&block)
	}
	b.mu.Unlock()
	if !exists {
		b.broadcastProposal(block)
	}
}

func (b *GossipBus) GetProposed(cycle uint64) *chain.Block {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.proposals[cycle]; ok {
		return chain.CloneBlock(p)
	}
	return nil
}

// PublishFinal stores the leader's finalised block for a cycle and gossips it.
func (b *GossipBus) PublishFinal(block chain.Block, proposerID string) {
	b.mu.Lock()
	b.finals[block.Index] = chain.CloneBlock(&block)
	b.mu.Unlock()
	b.broadcastProposal(block)
}

// GetFinal returns the finalised block for a cycle, or nil if the leader has not
// committed one yet.
func (b *GossipBus) GetFinal(cycle uint64) *chain.Block {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.finals[cycle]; ok {
		return chain.CloneBlock(p)
	}
	return nil
}

func (b *GossipBus) PublishSig(sig consensus.BlockSig) {
	b.mu.Lock()
	b.sigs[sig.Cycle] = append(b.sigs[sig.Cycle], sig)
	b.mu.Unlock()
	b.broadcastSig(sig)
}

func (b *GossipBus) GetSigs(cycle uint64) []consensus.BlockSig {
	b.mu.Lock()
	defer b.mu.Unlock()
	sigs := b.sigs[cycle]
	out := make([]consensus.BlockSig, len(sigs))
	copy(out, sigs)
	return out
}

// PublishVRFProof records this node's VRF proof for a cycle and gossips it.
//
// VRF proofs decide the proposer, so they cannot be reconstructed after the fact by
// the receiver the way a block can: each peer publishes its own and the selection
// reads all of them. First-write-wins per (cycle, signer) for the same reason
// Propose is first-write-wins — a signer must not be able to swap its proof after
// selection has read it.
func (b *GossipBus) PublishVRFProof(proof consensus.VRFProofMsg) {
	b.mu.Lock()
	for _, existing := range b.vrfProofs[proof.Cycle] {
		if existing.SignerID == proof.SignerID {
			b.mu.Unlock()
			return
		}
	}
	b.vrfProofs[proof.Cycle] = append(b.vrfProofs[proof.Cycle], proof)
	b.mu.Unlock()
	b.broadcastVRFProof(proof)
}

func (b *GossipBus) GetVRFProofs(cycle uint64) []consensus.VRFProofMsg {
	b.mu.Lock()
	defer b.mu.Unlock()
	proofs := b.vrfProofs[cycle]
	out := make([]consensus.VRFProofMsg, len(proofs))
	copy(out, proofs)
	return out
}

// --- Stream handlers ---

func (b *GossipBus) handleEntriesStream(s network.Stream) {
	defer func() { _ = s.Close() }()
	data, ok := readFramed(s)
	if !ok {
		log.Printf("%s: unreadable frame", s.Protocol())
		return
	}
	var entry chain.ProvenanceEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return
	}
	b.mu.Lock()
	b.pending = append(b.pending, entry)
	b.mu.Unlock()
}

func (b *GossipBus) handleProposalsStream(s network.Stream) {
	defer func() { _ = s.Close() }()
	data, ok := readFramed(s)
	if !ok {
		log.Printf("%s: unreadable frame", s.Protocol())
		return
	}
	var block chain.Block
	if err := json.Unmarshal(data, &block); err != nil {
		return
	}
	b.mu.Lock()
	b.proposals[block.Index] = &block
	b.mu.Unlock()
}

func (b *GossipBus) handleSigsStream(s network.Stream) {
	defer func() { _ = s.Close() }()
	data, ok := readFramed(s)
	if !ok {
		log.Printf("%s: unreadable frame", s.Protocol())
		return
	}
	var sig consensus.BlockSig
	if err := json.Unmarshal(data, &sig); err != nil {
		return
	}
	b.mu.Lock()
	b.sigs[sig.Cycle] = append(b.sigs[sig.Cycle], sig)
	b.mu.Unlock()
}

func (b *GossipBus) handleVRFProofsStream(s network.Stream) {
	defer func() { _ = s.Close() }()
	data, ok := readFramed(s)
	if !ok {
		log.Printf("%s: unreadable frame", s.Protocol())
		return
	}
	var proof consensus.VRFProofMsg
	if err := json.Unmarshal(data, &proof); err != nil {
		return
	}
	// Same first-write-wins rule as PublishVRFProof: a received proof must not
	// displace one already held for the same (cycle, signer).
	b.mu.Lock()
	for _, existing := range b.vrfProofs[proof.Cycle] {
		if existing.SignerID == proof.SignerID {
			b.mu.Unlock()
			return
		}
	}
	b.vrfProofs[proof.Cycle] = append(b.vrfProofs[proof.Cycle], proof)
	b.mu.Unlock()
}

// readFramed reads one length-prefixed frame from s.
//
// Two things are corrected here relative to the previous per-handler inline copies.
//
// The length is bounded by maxStreamMessage. A peer announcing 4 GiB would
// otherwise cause a 4 GiB allocation before any of the payload was validated.
//
// Reads are exact. stream.Read is permitted to return a short count, so the
// previous `if _, err := s.Read(data); err != nil` accepted a truncated frame as
// long as it read anything at all, and the JSON decoder was then asked to parse a
// partial message. io.ReadFull is the only correct way to consume a frame.
func readFramed(s network.Stream) ([]byte, bool) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
		return nil, false
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 || length > maxStreamMessage {
		return nil, false
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(s, data); err != nil {
		return nil, false
	}
	return data, true
}

// --- Broadcast helpers ---

func (b *GossipBus) broadcastEntry(entry chain.ProvenanceEntry) {
	data, _ := json.Marshal(entry)
	b.broadcast(protocolEntries, data)
}

func (b *GossipBus) broadcastProposal(block chain.Block) {
	data, _ := json.Marshal(block)
	b.broadcast(protocolProposals, data)
}

func (b *GossipBus) broadcastSig(sig consensus.BlockSig) {
	data, _ := json.Marshal(sig)
	b.broadcast(protocolSigs, data)
}

func (b *GossipBus) broadcastVRFProof(proof consensus.VRFProofMsg) {
	data, _ := json.Marshal(proof)
	b.broadcast(protocolVRFProofs, data)
}

// broadcast sends one framed message to every connected peer except this node.
func (b *GossipBus) broadcast(proto protocol.ID, data []byte) {
	peers := b.host.Network().Peers()
	if len(peers) == 0 {
		log.Printf("broadcast %s: no connected peers", proto)
		return
	}
	for _, pid := range peers {
		if pid == b.host.ID() {
			continue
		}
		go b.sendStream(pid, proto, data)
	}
}

// maxStreamMessage bounds a length-prefixed stream message.
//
// The prefix is a uint32. Without a check, a payload larger than 4 GiB would have its
// length truncated on the wire, so the peer would read a short frame and treat the
// remainder as the next frame's header. Rejecting here keeps the framing self-consistent
// for any peer that speaks it.
const maxStreamMessage = 4 * 1024 * 1024

func (b *GossipBus) sendStream(pid peer.ID, proto protocol.ID, data []byte) {
	if len(data) > maxStreamMessage {
		log.Printf("refusing to send %d bytes to %s: over the %d byte stream limit",
			len(data), pid, maxStreamMessage)
		return
	}

	ctx, cancel := context.WithTimeout(b.ctx, requestTimeout)
	defer cancel()

	s, err := b.host.NewStream(ctx, pid, proto)
	if err != nil {
		log.Printf("new stream to %s: %v", pid, err)
		return
	}
	defer func() { _ = s.Close() }()

	var lenBuf [4]byte
	// #nosec G115 -- len(data) cannot exceed maxStreamMessage, checked at the top of
	// this function, so this conversion cannot truncate.
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := s.Write(lenBuf[:]); err != nil {
		log.Printf("write length to %s on %s: %v", pid, proto, err)
		return
	}
	if _, err := s.Write(data); err != nil {
		log.Printf("write payload to %s on %s: %v", pid, proto, err)
		return
	}
	// CloseWrite, not Close.
	//
	// Close tears down the whole stream, which resets it at the remote end. The
	// receiver's read of the frame then fails with a stream reset instead of seeing
	// the data followed by EOF, so every gossipped message was silently dropped on
	// arrival. CloseWrite half-closes the sending side only, which is the signal the
	// reader is waiting for.
	if err := s.CloseWrite(); err != nil {
		log.Printf("close write to %s on %s: %v", pid, proto, err)
	}
}

func (b *GossipBus) Close() error {
	b.cancel()
	if b.discovery != nil {
		_ = b.discovery.Close()
	}
	return b.host.Close()
}

func (b *GossipBus) Host() host.Host {
	return b.host
}

func (b *GossipBus) ConnectedPeers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.connected)
}
