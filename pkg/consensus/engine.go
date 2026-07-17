// IPC consensus engine. Gleipnir is the reference implementation.
package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/smt"
	"github.com/had-nu/gleipnir/pkg/state"
)

type Engine struct {
	mu       sync.Mutex
	node     Node
	state    state.NetworkState
	cfg      state.Config
	st       *smt.SparseMerkleTree
	blocks   []chain.Block
	pending  []chain.ProvenanceEntry
	anchored map[[32]byte]*chain.AnchorProof

	cycleInterval time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
	nowFunc       func() time.Time // injectable clock, defaults to time.Now

	gossip    GossipChannel // nil for single-node mode
	peers     []Peer        // all network peers (including self)
	subChains *SubChainManager
	apiLimits APILimits
	stopped   bool

	storage    EngineStorage // optional persistence
	rateLimiter *SubmitterLimiter // sliding-window rate limiter

	quorumConfig chain.QuorumConfig
}

func NewEngine(node Node, cycleInterval time.Duration) *Engine {
	return newEngine(node, cycleInterval, nil, nil)
}

func NewEngineWithPeers(node Node, cycleInterval time.Duration, gossip GossipChannel, peers []Peer) *Engine {
	eng := newEngine(node, cycleInterval, gossip, peers)
	// Register all peers in state with full mesh edges
	var edges []state.Edge
	for _, p := range peers {
		uidHex := p.UID.ID()
		if _, ok := eng.state.Nodes[uidHex]; !ok {
			eng.state.Nodes[uidHex] = state.NodeState{
				UID:    p.UID.RootID,
				Status: 1.0,
			}
		}
		for _, q := range peers {
			edges = append(edges, state.Edge{From: uidHex, To: q.UID.ID(), Weight: 1.0})
		}
	}
	eng.state.Graph.Edges = edges
	return eng
}

func newEngine(node Node, cycleInterval time.Duration, gossip GossipChannel, peers []Peer) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	uidHex := node.UID.ID()
	if peers == nil {
		peers = []Peer{{UID: node.UID, Addr: node.Addr, Alive: true}}
	}
	// Default quorum: single-node = 1/1, multi-node = 3/3 (legacy)
	quorumCfg := chain.DefaultQuorumConfig()
	if len(peers) == 1 {
		quorumCfg = chain.QuorumConfig{TotalValidators: 1, RequiredSigs: 1}
	}
	eng := &Engine{
		node:          node,
		peers:         peers,
		gossip:        gossip,
		state:         state.NetworkState{Cycle: 0, Nodes: make(map[string]state.NodeState), Graph: state.ReputationGraph{}},
		cfg:           state.DefaultConfig,
		st:            smt.New(state.DefaultConfig.SMTDepth),
		blocks:        make([]chain.Block, 0),
		pending:       make([]chain.ProvenanceEntry, 0),
		anchored:      make(map[[32]byte]*chain.AnchorProof),
		cycleInterval: cycleInterval,
		ctx:           ctx,
		cancel:        cancel,
		nowFunc:       time.Now,
		rateLimiter:   NewSubmitterLimiter(5000, time.Minute), // 5000 per minute default
		quorumConfig:  quorumCfg,
	}
	eng.state.Nodes[uidHex] = state.NodeState{
		UID:    node.UID.RootID,
		Status: 1.0,
	}
	eng.state.Graph.Edges = []state.Edge{
		{From: uidHex, To: uidHex, Weight: 1.0},
	}
	return eng
}

func (e *Engine) Start() {
	go e.cycleLoop()
	log.Printf("IPC engine started, cycle interval=%v", e.cycleInterval)
}

func (e *Engine) Stop() {
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()
	e.cancel()
	// Persist state on stop
	if e.storage != nil {
		e.persist()
	}
}

// SetStorage sets the persistence backend for the engine.
func (e *Engine) SetStorage(s EngineStorage) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.storage = s
	// Load existing state if available
	if s != nil {
		e.loadPersisted()
	}
}

// persist saves engine state to storage.
func (e *Engine) persist() {
	if e.storage == nil {
		return
	}
	ctx := context.Background()
	_ = e.storage.SaveState(ctx, e.state)
	_ = e.storage.SavePending(ctx, e.pending)
	_ = e.storage.SaveSMT(ctx, e.st)
	for h, p := range e.anchored {
		_ = e.storage.SaveAnchored(ctx, h, p)
	}
	for _, b := range e.blocks {
		_ = e.storage.SaveBlock(ctx, b)
	}
}

// loadPersisted loads engine state from storage.
func (e *Engine) loadPersisted() {
	ctx := context.Background()
	if st, ok, _ := e.storage.LoadState(ctx); ok {
		e.state = st
	}
	if pending, err := e.storage.LoadPending(ctx); err == nil {
		e.pending = pending
	}
	if anchored, err := e.storage.LoadAnchored(ctx); err == nil {
		e.anchored = anchored
	}
	if blocks, err := e.storage.LoadBlocks(ctx); err == nil {
		e.blocks = blocks
	}
	if smtTree, err := e.storage.LoadSMT(ctx); err == nil && smtTree != nil {
		if t, ok := smtTree.(*smt.SparseMerkleTree); ok {
			e.st = t
		}
	}
}

func (e *Engine) SetQuorumConfig(config chain.QuorumConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if config.IsValid() {
		e.quorumConfig = config
	}
}

func (e *Engine) Enqueue(entry chain.ProvenanceEntry) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg := e.apiLimitsLocked()
	if err := validateEntry(entry.Hash, entry.Submitter, entry.Label, cfg); err != nil {
		return err
	}
	if len(e.pending) >= cfg.MaxTotalPending {
		return ErrRateLimited
	}
	// Use sliding-window rate limiter for per-submitter limit
	if e.rateLimiter != nil && !e.rateLimiter.Allow(entry.Submitter) {
		return ErrRateLimited
	}

	e.pending = append(e.pending, entry)
	if e.gossip != nil {
		e.gossip.Publish(entry)
	}
	return nil
}

func (e *Engine) LookupHash(hash [32]byte) (*chain.AnchorProof, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	proof, ok := e.anchored[hash]
	if ok {
		return proof, true
	}
	return nil, false
}

func (e *Engine) GetHealth() chain.NetworkHealth {
	e.mu.Lock()
	defer e.mu.Unlock()
	active := 0
	for _, n := range e.state.Nodes {
		if n.Status > 0 {
			active++
		}
	}
	return chain.NetworkHealth{
		Lambda1:       e.state.Lambda1,
		ActivePeers:   active,
		TotalPeers:    len(e.state.Nodes),
		BlockHeight:   uint64(len(e.blocks)),
		PendingHashes: len(e.pending),
	}
}

func (e *Engine) PendingCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.pending)
}

func (e *Engine) countPendingBySubmitter(submitter []byte) int {
	count := 0
	for _, e := range e.pending {
		if string(e.Submitter) == string(submitter) {
			count++
		}
	}
	return count
}

func (e *Engine) GetStateRoot() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.st.Root()
	return r[:]
}

func (e *Engine) Cycle() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state.Cycle
}

func (e *Engine) GetBlock(index uint64) *chain.Block {
	e.mu.Lock()
	defer e.mu.Unlock()
	if index >= uint64(len(e.blocks)) {
		return nil
	}
	return &e.blocks[index]
}

func (e *Engine) BlockCount() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return uint64(len(e.blocks))
}

func (e *Engine) cycleLoop() {
	ticker := time.NewTicker(e.cycleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.RunCycle()
		}
	}
}

func (e *Engine) RunCycle() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("IPC cycle panic recovered: %v", r)
		}
	}()
	e.mu.Lock()
	defer e.mu.Unlock()

	cycle := e.state.Cycle
	myUIDHex := e.node.UID.ID()

	if e.gossip != nil {
		e.pending = e.pending[:0]
	}

	rootArr := e.st.Root()
	proposerPeers := e.peers
	if e.gossip == nil {
		proposerPeers = []Peer{{UID: e.node.UID, Addr: e.node.Addr, Alive: true}}
	}

	// Compute local VRF proof for proposer selection
	alpha := makeAlpha(cycle, rootArr[:])
	localProof, vrfErr := e.node.UID.VRFProve(alpha)
	if vrfErr != nil {
		log.Printf("IPC cycle %d: VRF proof error: %v", cycle, vrfErr)
		e.state.Cycle++
		return
	}

	// Publish VRF proof to gossip network
	if e.gossip != nil {
		proofBytes := identity.MarshalVRFProof(localProof)
		e.gossip.PublishVRFProof(VRFProofMsg{Cycle: cycle, Proof: proofBytes, SignerID: myUIDHex})
	}

	// Collect all VRF proofs (local + from gossip)
	vrfProofs := make(map[string]*identity.VRFProof)
	vrfProofs[myUIDHex] = localProof
	if e.gossip != nil {
		for _, msg := range e.gossip.GetVRFProofs(cycle) {
			p, err := identity.UnmarshalVRFProof(msg.Proof)
			if err == nil {
				if _, exists := vrfProofs[msg.SignerID]; !exists {
					vrfProofs[msg.SignerID] = p
				}
			}
		}
	}

	proposer, _, vrfErr := SelectProposer(proposerPeers, cycle, rootArr[:], vrfProofs)
	if vrfErr != nil {
		log.Printf("IPC cycle %d: VRF proposer selection failed: %v", cycle, vrfErr)
		e.state.Cycle++
		return
	}
	proposerHex := proposer.UID.ID()
	amProposer := proposerHex == myUIDHex

	if nodeState, ok := e.state.Nodes[proposerHex]; ok && nodeState.Status <= 0 {
		log.Printf("IPC cycle %d: proposer %s is inactive, skipping", cycle, proposerHex)
		e.state.Cycle++
		return
	}

	prevHash := make([]byte, 32)
	if len(e.blocks) > 0 {
		prevHash = e.blocks[len(e.blocks)-1].BlockHash
	}

	var entries []chain.ProvenanceEntry
	var block chain.Block

	if amProposer {
		// Proposer: collect entries from gossip snapshot
		if e.gossip != nil {
			entries = e.gossip.Snapshot()
		} else {
			entries = make([]chain.ProvenanceEntry, len(e.pending))
			copy(entries, e.pending)
			e.pending = e.pending[:0]
		}

		if len(entries) == 0 {
			e.state.Cycle++
			return
		}

		seen := make(map[[32]byte]int)
		unique := make([]chain.ProvenanceEntry, 0, len(entries))
		for _, entry := range entries {
			if _, dup := seen[entry.Hash]; !dup {
				seen[entry.Hash] = 1
				unique = append(unique, entry)
			}
		}
		entries = unique

		block = chain.Block{
			Index:      cycle,
			PrevHash:   prevHash,
			Proposer:   proposer.UID.RootID,
			Anchored:   entries,
			Lambda1:    e.state.Lambda1,
			Timestamp:  e.nowFunc().UnixNano(),
			Quorum:     e.quorumConfig,
			Validators: make([][]byte, 0, len(e.peers)),
			Sigs:       make([][]byte, 0, len(e.peers)),
		}

		for _, p := range e.peers {
			block.Validators = append(block.Validators, p.UID.PublicKey)
		}

		for i := range entries {
			var h [32]byte
			copy(h[:], entries[i].Hash[:])
			e.st.Insert(h[:], entries[i].Hash[:])

			proof, _ := e.st.Prove(h[:])
			proofBytes := make([]byte, 0, len(proof)*32)
			for _, p := range proof {
				proofBytes = append(proofBytes, p[:]...)
			}
			stateRootArr := e.st.Root()
		e.anchored[h] = &chain.AnchorProof{
			Found:      true,
			BlockIndex: uint64(len(e.blocks)),
			BlockTime:  block.Timestamp,
			StateRoot:  stateRootArr[:],
			SMTProof:   proofBytes,
			Submitter:  entries[i].Submitter,
			Label:      entries[i].Label,
		}
	}

	stateRootArr := e.st.Root()
	block.StateRoot = stateRootArr[:]
		blockHash := computeBlockHash(block)
		block.BlockHash = blockHash

		// Proposer signs first
		proposerSig := identity.SignDilithium(e.node.UID.SecretKey, blockHash)
		block.Sigs = append(block.Sigs, proposerSig)

		if e.gossip != nil {
			e.gossip.Propose(block, myUIDHex)
			e.gossip.PublishSig(BlockSig{Cycle: cycle, Sig: proposerSig, SignerID: myUIDHex})
		}
	} else {
		// Non-proposer: read proposer's block from gossip
		if e.gossip == nil {
			e.state.Cycle++
			return
		}
		proposal := e.gossip.GetProposed(cycle)
		if proposal == nil {
			log.Printf("IPC cycle %d: no proposal from proposer %s, skipping", cycle, proposerHex)
			e.state.Cycle++
			return
		}
		block = *proposal
		entries = block.Anchored

		// Insert entries into SMT (must match proposer's root)
		for i := range entries {
			var h [32]byte
			copy(h[:], entries[i].Hash[:])
			e.st.Insert(h[:], entries[i].Hash[:])

			proof, _ := e.st.Prove(h[:])
			proofBytes := make([]byte, 0, len(proof)*32)
			for _, p := range proof {
				proofBytes = append(proofBytes, p[:]...)
			}
			stateRootArr := e.st.Root()
			e.anchored[h] = &chain.AnchorProof{
				Found:      true,
				BlockIndex: uint64(len(e.blocks)),
				BlockTime:  block.Timestamp,
				StateRoot:  stateRootArr[:],
				SMTProof:   proofBytes,
				Submitter:  entries[i].Submitter,
				Label:      entries[i].Label,
			}
		}

		// Verify SMT root matches proposer's
		localRoot := e.st.Root()
		if string(localRoot[:]) != string(block.StateRoot) {
			log.Printf("IPC cycle %d: SMT root mismatch, local=%x proposal=%x",
				cycle, localRoot[:], block.StateRoot)
			e.state.Cycle++
			return
		}

		mySig := identity.SignDilithium(e.node.UID.SecretKey, block.BlockHash)
		e.gossip.PublishSig(BlockSig{Cycle: cycle, Sig: mySig, SignerID: myUIDHex})
	}

	// Collect signatures from all peers (flexible quorum)
	if e.gossip != nil && len(e.peers) >= 3 {
		sigs := e.gossip.GetSigs(cycle)
		sigMap := make(map[string][]byte)
		for _, s := range sigs {
			sigMap[s.SignerID] = s.Sig
		}

			validSigs := make([][]byte, 0, len(e.peers))
		for _, p := range e.peers {
			if sig, ok := sigMap[p.UID.ID()]; ok && len(sig) > 0 {
				validSigs = append(validSigs, sig)
			}
		}
		block.Sigs = validSigs
	}

	// Note: Quorum verification is now done by the caller after all engines
	// have run their RunCycle for the current cycle. This allows all peers
	// to sign before quorum is verified.

	next, err := state.Apply(e.state, e.state.SupervisionRoot, []string{myUIDHex}, e.cfg)
	if err != nil {
		e.state.Cycle++
		log.Printf("IPC cycle %d: state apply error: %v (λ₁=%.4f, min=%.4f, block not appended)",
			cycle, err, e.state.Lambda1, e.cfg.MinLambda1)
		return
	}
	e.state = next
	e.blocks = append(e.blocks, block)

	// Persist state after successful block append
	if e.storage != nil {
		e.persist()
	}

	// Remove committed entries from gossip pool
	if e.gossip != nil && amProposer {
		remove := make(map[[32]byte]bool)
		for _, entry := range entries {
			remove[entry.Hash] = true
		}
		e.gossip.RemoveEntries(remove)
	}

	log.Printf("IPC cycle %d: block anchored with %d entries, root=%x, λ₁=%.4f",
		cycle, len(entries), block.StateRoot, e.state.Lambda1)
}

func findProposerIndex(peers []Peer, proposerHex string) int {
	for i, p := range peers {
		if p.UID.ID() == proposerHex {
			return i
		}
	}
	return 0
}

func (e *Engine) WaitForAnchor(ctx context.Context, hash [32]byte) (*chain.AnchorProof, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			e.mu.Lock()
			proof, ok := e.anchored[hash]
			e.mu.Unlock()
			if ok {
				return proof, nil
			}
		}
	}
}

func (e *Engine) SubChains() *SubChainManager {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.subChains == nil {
		e.subChains = NewSubChainManager(e)
	}
	return e.subChains
}

func (e *Engine) ProveSMT(key []byte) ([][32]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st.Prove(key)
}

// Anchorer interface implementation.

func (e *Engine) Submit(ctx context.Context, hash [32]byte, submitter []byte, label string) (*chain.Ticket, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.stopped {
		return nil, ErrEngineStopped
	}

	cfg := e.apiLimitsLocked()
	if err := validateEntry(hash, submitter, label, cfg); err != nil {
		return nil, err
	}
	if len(e.pending) >= cfg.MaxTotalPending {
		return nil, ErrRateLimited
	}
	// Use sliding-window rate limiter for per-submitter limits
	if e.rateLimiter != nil && !e.rateLimiter.Allow(submitter) {
		return nil, ErrRateLimited
	}

	e.pending = append(e.pending, chain.ProvenanceEntry{
		Hash:      hash,
		Submitter: submitter,
		Timestamp: time.Now().UnixNano(),
		Label:     label,
	})
	estimatedBlock := uint64(len(e.blocks))
	return &chain.Ticket{
		Hash:       hash,
		Status:     "pending",
		BlockIndex: estimatedBlock,
	}, nil
}

func (e *Engine) VerifyHash(ctx context.Context, hash [32]byte) (*chain.AnchorProof, error) {
	proof, found := e.verifyHash(hash)
	if !found {
		return nil, fmt.Errorf("hash not found")
	}
	return proof, nil
}

func (e *Engine) GetNetworkHealth(ctx context.Context) (*chain.NetworkHealth, error) {
	h := e.GetHealth()
	return &h, nil
}

func (e *Engine) Close() error {
	e.Stop()
	return nil
}

func (e *Engine) verifyHash(hash [32]byte) (*chain.AnchorProof, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	proof, ok := e.anchored[hash]
	if ok {
		return proof, true
	}
	return nil, false
}

func computeBlockHash(b chain.Block) []byte {
	h := sha256.New()
	binary.Write(h, binary.LittleEndian, b.Index)
	h.Write(b.PrevHash)
	h.Write(b.StateRoot)
	h.Write(b.Proposer)
	for _, e := range b.Anchored {
		h.Write(e.Hash[:])
	}
	binary.Write(h, binary.LittleEndian, b.Timestamp)
	return h.Sum(nil)
}
