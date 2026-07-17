// libp2p GossipChannel implementation for multi-node consensus.
package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
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

	dialTimeout    = 10 * time.Second
	requestTimeout = 30 * time.Second
)

type Config struct {
	ListenAddrs      []string
	BootstrapPeers   []string
	EnableMDNS       bool
	MDNSServiceTag   string
	PrivateKeyFile   string
	NodeID           string
}

type GossipBus struct {
	host       host.Host
	discovery  mdns.Service
	notifee    *mdnsNotifee //nolint:unused

	mu        sync.Mutex
	pending   []chain.ProvenanceEntry
	proposals map[uint64]*chain.Block
	sigs      map[uint64][]consensus.BlockSig
	connected map[peer.ID]bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup //nolint:unused
}

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

func NewGossipBus(ctx context.Context, cfg Config) (*GossipBus, error) {
	ctx, cancel := context.WithCancel(ctx)

	// Generate or load libp2p identity
	var privKey crypto.PrivKey
	var err error
	if cfg.PrivateKeyFile != "" {
		// TODO: load from file
		_ = cfg.PrivateKeyFile
	}
	if privKey == nil {
		privKey, _, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("generate key: %w", err)
		}
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
		host:       h,
		proposals:  make(map[uint64]*chain.Block),
		sigs:       make(map[uint64][]consensus.BlockSig),
		connected:  make(map[peer.ID]bool),
		ctx:        ctx,
		cancel:     cancel,
	}
	notifee.bus = bus

	h.SetStreamHandler(protocolEntries, bus.handleEntriesStream)
	h.SetStreamHandler(protocolProposals, bus.handleProposalsStream)
	h.SetStreamHandler(protocolSigs, bus.handleSigsStream)

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

	log.Printf("P2P host started: %s (peers: %d)", h.ID(), len(h.Network().Peers()))
	return bus, nil
}

func (b *GossipBus) connectToPeer(addrStr string) {
	ma, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		log.Printf("parse bootstrap addr %s: %v", addrStr, err)
		return
	}
	pi, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		log.Printf("addr info from %s: %v", addrStr, err)
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

func (b *GossipBus) Propose(block chain.Block, proposerID string) {
	b.mu.Lock()
	b.proposals[block.Index] = &block
	b.mu.Unlock()
	b.broadcastProposal(block)
}

func (b *GossipBus) GetProposed(cycle uint64) *chain.Block {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.proposals[cycle]; ok {
		cp := *p
		return &cp
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

// --- Stream handlers ---

func (b *GossipBus) handleEntriesStream(s network.Stream) {
	defer func() { _ = s.Close() }()
	var lenBuf [4]byte
	if _, err := s.Read(lenBuf[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	data := make([]byte, length)
	if _, err := s.Read(data); err != nil {
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
	var lenBuf [4]byte
	if _, err := s.Read(lenBuf[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	data := make([]byte, length)
	if _, err := s.Read(data); err != nil {
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
	var lenBuf [4]byte
	if _, err := s.Read(lenBuf[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	data := make([]byte, length)
	if _, err := s.Read(data); err != nil {
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

// --- Broadcast helpers ---

func (b *GossipBus) broadcastEntry(entry chain.ProvenanceEntry) {
	data, _ := json.Marshal(entry)
	peers := b.host.Network().Peers()
	for _, pid := range peers {
		if pid == b.host.ID() {
			continue
		}
		go b.sendStream(pid, protocolEntries, data)
	}
}

func (b *GossipBus) broadcastProposal(block chain.Block) {
	data, _ := json.Marshal(block)
	peers := b.host.Network().Peers()
	for _, pid := range peers {
		if pid == b.host.ID() {
			continue
		}
		go b.sendStream(pid, protocolProposals, data)
	}
}

func (b *GossipBus) broadcastSig(sig consensus.BlockSig) {
	data, _ := json.Marshal(sig)
	peers := b.host.Network().Peers()
	for _, pid := range peers {
		if pid == b.host.ID() {
			continue
		}
		go b.sendStream(pid, protocolSigs, data)
	}
}

func (b *GossipBus) sendStream(pid peer.ID, proto protocol.ID, data []byte) {
	ctx, cancel := context.WithTimeout(b.ctx, requestTimeout)
	defer cancel()

	s, err := b.host.NewStream(ctx, pid, proto)
	if err != nil {
		log.Printf("new stream to %s: %v", pid, err)
		return
	}
	defer func() { _ = s.Close() }()

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := s.Write(lenBuf[:]); err != nil {
		return
	}
	if _, err := s.Write(data); err != nil {
		return
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