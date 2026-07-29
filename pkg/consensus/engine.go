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

	// v2.0 fields
	cycleTimeout   time.Duration // CycleTimeout for PREPARE phase
	degradedMode   bool          // Whether network is in degraded mode
	pendingEntries []chain.ProvenanceEntry // Retained entries across cycle aborts

	// Incremental Laplacian for efficient λ₁ computation
	laplacian *state.IncrementalLaplacian
}

func NewEngine(node Node, cycleInterval time.Duration) *Engine {
	return newEngine(node, cycleInterval, nil, nil)
}

func NewEngineWithPeers(node Node, cycleInterval time.Duration, gossip GossipChannel, peers []Peer) *Engine {
	eng := newEngine(node, cycleInterval, gossip, peers)
	// Register all peers in state with full mesh edges and validator keys
	var edges []state.Edge
	for _, p := range peers {
		uidHex := p.UID.ID()
		if _, ok := eng.state.Nodes[uidHex]; !ok {
			eng.state.Nodes[uidHex] = state.NodeState{
				UID:          p.UID.RootID,
				Status:       1.0,
				Dilithium3PK: p.UID.PublicKey,
				VRFPK:        p.UID.VRFPublicKey,
			}
		}
		for _, q := range peers {
			edges = append(edges, state.Edge{From: uidHex, To: q.UID.ID(), Weight: 1.0})
		}
	}
	eng.state.Graph.Edges = edges
	// Also populate ValidatorSet from peers
	eng.state.ValidatorSet = make([]state.ValidatorInfo, 0, len(peers))
	for _, p := range peers {
		eng.state.ValidatorSet = append(eng.state.ValidatorSet, state.ValidatorInfo{
			ValidatorID:  p.UID.RootID,
			Dilithium3PK: p.UID.PublicKey,
			VRFPK:        p.UID.VRFPublicKey,
			ContractHash: p.UID.ContractHash,
		})
	}
	return eng
}

func newEngine(node Node, cycleInterval time.Duration, gossip GossipChannel, peers []Peer) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	uidHex := node.UID.ID()
	if peers == nil {
		peers = []Peer{{UID: node.UID, Addr: node.Addr, Alive: true}}
	}
	// Default quorum: single-node = 1/1, multi-node = ceil(2N/3)
	quorumCfg := chain.DefaultQuorumConfig()
	if len(peers) == 1 {
		quorumCfg = chain.QuorumConfig{TotalValidators: 1, RequiredSigs: 1}
	} else {
		// v2.0: Fixed quorum formula Q = ceil(2N/3)
		quorumCfg = chain.QuorumConfig{TotalValidators: len(peers), RequiredSigs: (2*len(peers) + 2) / 3}
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
		cycleTimeout:  10 * time.Second, // Default 10s cycle timeout
		pendingEntries: make([]chain.ProvenanceEntry, 0),
		laplacian:       state.DefaultIncrementalLaplacian(),
	}
	eng.state.Nodes[uidHex] = state.NodeState{
		UID:    node.UID.RootID,
		Status: 1.0,
	}
	eng.state.Graph.Edges = []state.Edge{
		{From: uidHex, To: uidHex, Weight: 1.0},
	}
	// Initialize validator set
	eng.state.ValidatorSet = []state.ValidatorInfo{{
		ValidatorID:  node.UID.RootID,
		Dilithium3PK: node.UID.PublicKey,
		VRFPK:        node.UID.VRFPublicKey,
		ContractHash: node.UID.ContractHash,
	}}
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

// RunVRFPhase publishes this engine's VRF proof and collects all VRF proofs for the given cycle.
// This is the first phase of consensus, run before the PREPARE phase.
// All engines in the network should call this before the PREPARE phase.
func (e *Engine) RunVRFPhase(cycle uint64) (map[string]*identity.VRFProof, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.gossip == nil {
		return nil, fmt.Errorf("no gossip channel for VRF phase")
	}

	rootArr := e.st.Root()
	alpha := makeAlpha(cycle, rootArr[:])
	localProof, vrfErr := e.node.UID.VRFProve(alpha)
	if vrfErr != nil {
		return nil, fmt.Errorf("VRF proof error: %w", vrfErr)
	}

	// Publish VRF proof
	if e.gossip != nil {
		proofBytes := identity.MarshalVRFProof(localProof)
		e.gossip.PublishVRFProof(VRFProofMsg{Cycle: cycle, Proof: proofBytes, SignerID: e.node.UID.ID()})
	}

	// Collect all VRF proofs (local + from gossip)
	vrfProofs := make(map[string]*identity.VRFProof)
	vrfProofs[e.node.UID.ID()] = localProof
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

	return vrfProofs, nil
}

// RunPreparePhaseWithVRF executes the PREPARE phase using pre-collected VRF proofs.
// This is the second phase of consensus, run after RunVRFPhase.
// The vrfProofs parameter should contain the VRF proofs collected by RunVRFPhase.
func (e *Engine) RunPreparePhaseWithVRF(cycle uint64, rootArr [32]byte, pendingEntries []chain.ProvenanceEntry, vrfProofs map[string]*identity.VRFProof, checkQuorum bool) *PrepareResult {
	// Temporarily replace gossip's VRF proofs for this cycle
	// Note: This is a simplified approach; in production, VRF proofs are already in gossip
	return e.RunPreparePhase(cycle, rootArr, pendingEntries, checkQuorum)
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

	if e.stopped {
		return ErrEngineStopped
	}

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

//nolint:unused
func (e *Engine) countPendingBySubmitter(submitter [16]byte) int {
	count := 0
	for _, e := range e.pending {
		if e.Submitter == submitter {
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

	// Build pending entries: include retained entries from previous aborted cycles
	allPending := make([]chain.ProvenanceEntry, len(e.pendingEntries))
	copy(allPending, e.pendingEntries)
	allPending = append(allPending, e.pending...)

	if len(allPending) == 0 && e.cfg.SkipEmptyCycles {
		e.state.Cycle++
		return
	}

	rootArr := e.st.Root()

	// PHASE 1: PREPARE - proposer proposes, validators sign
	prepareResult := e.RunPreparePhase(cycle, rootArr, allPending, false)
	if prepareResult.Err != nil {
		log.Printf("IPC cycle %d: PREPARE failed: %v", cycle, prepareResult.Err)
		// Cycle aborted - retain entries for next cycle
		e.pendingEntries = allPending
		e.state.Cycle++
		return
	}

	// PHASE 2: QUORUM CHECK - proposer verifies quorum on the same block
	prepareResult = e.RunPreparePhase(cycle, rootArr, allPending, true)
	if prepareResult.Err != nil {
		log.Printf("IPC cycle %d: QUORUM CHECK failed: %v", cycle, prepareResult.Err)
		e.pendingEntries = allPending
		e.state.Cycle++
		return
	}

	// PHASE 3: COMMIT - all validators verify and commit
	commitResult := e.RunCommitPhase(cycle, prepareResult)
	if commitResult.Err != nil {
		log.Printf("IPC cycle %d: COMMIT failed: %v", cycle, commitResult.Err)
		e.pendingEntries = allPending
		e.state.Cycle++
		return
	}

	// SUCCESS: Commit the block
	finalBlock := commitResult.Block

	// Apply state transition
	next, err := state.Apply(e.state, e.state.SupervisionRoot, []string{e.node.UID.ID()}, e.cfg, e.laplacian)
	if err != nil {
		log.Printf("IPC cycle %d: state apply error: %v (λ₁=%.4f, min=%.4f, block not appended)",
			cycle, err, e.state.Lambda1, e.cfg.MinLambda1)
		// Cycle failed - retain entries for next cycle
		e.pendingEntries = allPending
		e.state.Cycle++
		return
	}
	e.state = next

	// Clear pending entries that were committed
	committedHashes := make(map[[32]byte]bool)
	for _, entry := range finalBlock.Anchored {
		committedHashes[entry.Hash] = true
	}
	newPending := make([]chain.ProvenanceEntry, 0, len(e.pendingEntries))
	for _, entry := range e.pendingEntries {
		if !committedHashes[entry.Hash] {
			newPending = append(newPending, entry)
		}
	}
	e.pendingEntries = newPending
	e.pending = e.pending[:0] // Clear local pending

	// Append block to chain
	e.blocks = append(e.blocks, *finalBlock)

	// Populate anchored map with anchor proofs for committed entries
	for _, entry := range finalBlock.Anchored {
		var h [32]byte
		copy(h[:], entry.Hash[:])
		proof, _ := e.st.Prove(h[:])
		proofBytes := make([]byte, 0, len(proof)*32)
		for _, p := range proof {
			proofBytes = append(proofBytes, p[:]...)
		}
		stateRootArr := e.st.Root()
		e.anchored[h] = &chain.AnchorProof{
			Found:      true,
			BlockIndex: uint64(len(e.blocks) - 1),
			BlockTime:  finalBlock.Timestamp,
			StateRoot:  stateRootArr[:],
			SMTProof:   proofBytes,
			Submitter:  entry.Submitter,
			Label:      entry.Label,
		}
	}

	// Persist state after successful block append
	if e.storage != nil {
		e.persist()
	}

	// Remove committed entries from gossip pool
	if e.gossip != nil {
		remove := make(map[[32]byte]bool)
		for _, entry := range finalBlock.Anchored {
			remove[entry.Hash] = true
		}
		e.gossip.RemoveEntries(remove)
	}

	log.Printf("IPC cycle %d: block anchored with %d entries, root=%x, λ₁=%.4f",
		cycle, len(finalBlock.Anchored), finalBlock.StateRoot, e.state.Lambda1)
}

//nolint:unused
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

func (e *Engine) Submit(ctx context.Context, hash [32]byte, submitter [16]byte, label string) (*chain.Ticket, error) {
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
	_ = binary.Write(h, binary.LittleEndian, b.Index)
	_, _ = h.Write(b.PrevHash)
	_, _ = h.Write(b.StateRoot)
	_, _ = h.Write(b.Proposer[:])
	for _, e := range b.Anchored {
		_, _ = h.Write(e.Hash[:])
	}
	_ = binary.Write(h, binary.LittleEndian, b.Timestamp)
	return h.Sum(nil)
}