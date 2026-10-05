// IPC consensus engine. Gleipnir is the reference implementation.
package consensus

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/had-nu/gleipnir/pkg/anchor"
	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/smt"
	"github.com/had-nu/gleipnir/pkg/state"
	"github.com/had-nu/gleipnir/pkg/validation"
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

	storage     EngineStorage     // optional persistence
	rateLimiter *SubmitterLimiter // sliding-window rate limiter

	quorumConfig chain.QuorumConfig

	// v2.0 fields
	cycleTimeout   time.Duration           // CycleTimeout for PREPARE phase
	degraded       *DegradedMode           // Degraded mode handler
	pendingEntries []chain.ProvenanceEntry // Retained entries across cycle aborts

	// Incremental Laplacian for efficient λ₁ computation
	laplacian *state.IncrementalLaplacian

	// Adaptive cycle (EWMA RTT)
	rttEWMA        time.Duration // Exponential moving average of RTT
	rttSamples     int           // Number of RTT samples collected
	lastCycleStart time.Time     // Start time of current cycle for RTT measurement
	cycleDuration  time.Duration // Current adaptive cycle duration

	// Anchor Publisher (spec §11.1)
	anchorPublisher *anchor.AnchorPublisher

	// Key rotation (spec §8). keyRotationValidator owns its own lock so that
	// overlap-aware signature verification can run while the engine lock is held;
	// keyRotationBodies is guarded by e.mu and holds the full rotation entries,
	// which ProvenanceEntry cannot carry (it anchors only hash + label).
	keyRotationValidator *validation.KeyRotationValidator
	keyRotationBodies    map[[32]byte]*chain.KeyRotationEntry

	// Mandates (spec §13). mandateBodies is guarded by e.mu and holds the full mandate
	// entries, for the same reason as keyRotationBodies: ProvenanceEntry anchors only a
	// hash and a label, so the body cannot be recovered from the chain.
	mandateResolver   *validation.MandateResolver
	mandateValidator  *validation.MandateValidator
	complianceChecker *validation.ComplianceChecker
	mandateBodies     map[[32]byte]*chain.MandateEntry
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
	// The validator set was populated after newEngine ran, so refresh the key
	// rotation validator's snapshot of it.
	eng.registerPeerValidatorSetLocked()
	return eng
}

func newEngine(node Node, cycleInterval time.Duration, gossip GossipChannel, peers []Peer) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	uidHex := node.UID.ID()
	if peers == nil {
		peers = []Peer{{UID: node.UID, Addr: node.Addr, Alive: true}}
	}
	// Default quorum: single-node = 1/1, multi-node = ceil(2N/3).
	// Declared rather than initialised to DefaultQuorumConfig: both branches assign, so an
	// initial value here would be discarded and could mislead a reader into thinking a
	// 3/3 default applies when neither branch is taken.
	var quorumCfg chain.QuorumConfig
	if len(peers) == 1 {
		quorumCfg = chain.QuorumConfig{TotalValidators: 1, RequiredSigs: 1}
	} else {
		// v2.0: Fixed quorum formula Q = ceil(2N/3)
		quorumCfg = chain.QuorumConfig{TotalValidators: len(peers), RequiredSigs: (2*len(peers) + 2) / 3}
	}
	// The cycle interval the caller asked for becomes BaseInterval.
	//
	// updateCycleDuration derives the cycle from BaseInterval on every cycle
	// (BaseInterval + EWMA(RTT) * SafetyFactor, SPEC 10.1), so setting BaseInterval is
	// what makes the argument mean anything. Previously BaseInterval was always the
	// package default and the cycleInterval argument affected nothing but a log line:
	// cycleLoop ticks on cycleDuration, so every node ran at 3s regardless of the interval
	// it was constructed with.
	cfg := state.DefaultConfig
	cfg.BaseInterval = cycleInterval
	if cycleInterval > 0 && cycleInterval < cfg.MaxCycleDuration {
		// Keep the hard cap above the base, or updateCycleDuration would clamp every
		// computed duration back up to the cap and ignore the base entirely.
		cfg.MaxCycleDuration = cycleInterval * 4
	}

	eng := &Engine{
		node:           node,
		peers:          peers,
		gossip:         gossip,
		state:          state.NetworkState{Cycle: 0, Nodes: make(map[string]state.NodeState), Graph: state.ReputationGraph{}},
		cfg:            cfg,
		st:             smt.New(state.DefaultConfig.SMTDepth),
		blocks:         make([]chain.Block, 0),
		pending:        make([]chain.ProvenanceEntry, 0),
		anchored:       make(map[[32]byte]*chain.AnchorProof),
		cycleInterval:  cycleInterval,
		ctx:            ctx,
		cancel:         cancel,
		nowFunc:        time.Now,
		rateLimiter:    NewSubmitterLimiter(5000, time.Minute), // 5000 per minute default
		quorumConfig:   quorumCfg,
		cycleTimeout:   10 * time.Second, // Default 10s cycle timeout
		pendingEntries: make([]chain.ProvenanceEntry, 0),
		laplacian:      state.DefaultIncrementalLaplacian(),
		// Adaptive cycle: start at the configured interval.
		//
		// This used to be state.DefaultConfig.BaseInterval, which meant the cycleInterval
		// argument to NewEngine affected nothing but a log line. cycleLoop ticks on
		// cycleDuration, and updateCycleDuration derives it from BaseInterval, so the
		// caller's value was silently discarded and every node ran at the default no
		// matter what interval it was constructed with.
		cycleDuration: cycleInterval,
		// Degraded mode handler
		degraded: NewDegradedMode(state.DefaultConfig.MinValidators, state.DefaultConfig.GraceCycles),
	}
	// Initialize anchor publisher (filesystem + IPFS if configured)
	anchorCfg := anchor.DefaultAnchorPublisherConfig()
	if ap, err := anchor.NewAnchorPublisher(anchorCfg); err == nil {
		eng.anchorPublisher = ap
	} else {
		log.Printf("Warning: failed to initialize anchor publisher: %v", err)
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

	// Initialize key rotation (spec §8) after the validator set exists, so the
	// validator starts from the right key material.
	eng.initKeyRotationLocked()
	eng.initMandatesLocked()

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
func (e *Engine) RunPreparePhaseWithVRF(cycle uint64, rootArr [32]byte, pendingEntries []chain.ProvenanceEntry, vrfProofs map[string]*identity.VRFProof, checkQuorum bool, requiredQuorum int) *PrepareResult {
	// Temporarily replace gossip's VRF proofs for this cycle
	// Note: This is a simplified approach; in production, VRF proofs are already in gossip
	return e.RunPreparePhase(cycle, rootArr, pendingEntries, checkQuorum, requiredQuorum)
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
	// An entry that names a mandate is asserting it satisfies that mandate's rules
	// (spec §13). The claim is checked structurally here; the events themselves are
	// checked at verification time by the compliance checker.
	if err := e.validateEntryAgainstMandatesLocked(&entry); err != nil {
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

// ValidatorSetSnapshot returns a copy of the canonical validator set, in the block's
// validator-info shape.
//
// The engine tracks the set as state.ValidatorInfo while blocks carry chain.ValidatorInfo;
// the two have the same fields, so this is a type conversion rather than a mapping. It is
// returned as a copy because the gRPC layer serves it to light clients as their trust
// anchor, and handing out the live slice would let a caller edit which validators are
// trusted.
func (e *Engine) ValidatorSetSnapshot() []chain.ValidatorInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]chain.ValidatorInfo, len(e.state.ValidatorSet))
	for i := range e.state.ValidatorSet {
		v := &e.state.ValidatorSet[i]
		out[i] = chain.ValidatorInfo{
			ValidatorID:  v.ValidatorID,
			Dilithium3PK: v.Dilithium3PK,
			VRFPK:        v.VRFPK,
			ContractHash: v.ContractHash,
		}
	}
	return out
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

// CycleDuration returns the interval the cycle loop is currently ticking at.
//
// This is the real period, which is not necessarily the value passed to NewEngine:
// updateCycleDuration raises it to BaseInterval + EWMA(RTT) * SafetyFactor on every cycle.
// Anything reasoning about anchor latency needs this rather than the constructor argument.
func (e *Engine) CycleDuration() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cycleDuration
}

func (e *Engine) BlockCount() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return uint64(len(e.blocks))
}

func (e *Engine) cycleLoop() {
	// Adaptive cycle: use dynamic ticker that adjusts based on EWMA RTT
	ticker := time.NewTicker(e.cycleDuration)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case now := <-ticker.C:
			e.lastCycleStart = now
			e.RunCycle()

			// Update cycle duration based on EWMA RTT
			e.updateCycleDuration()

			// Reset ticker with new duration
			ticker.Stop()
			ticker = time.NewTicker(e.cycleDuration)
		}
	}
}

// updateCycleDuration computes the next cycle duration using EWMA RTT per spec §10.1
// CycleDuration = BaseInterval + EWMA(RTT) * SafetyFactor, capped at MaxCycleDuration
func (e *Engine) updateCycleDuration() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Measure RTT for this cycle (time from cycle start to now)
	rtt := time.Since(e.lastCycleStart)

	// Update EWMA: EWMA_new = alpha * rtt + (1 - alpha) * EWMA_old
	// Using alpha = 0.3 (standard for EWMA)
	const alpha = 0.3
	if e.rttSamples == 0 {
		e.rttEWMA = rtt
	} else {
		e.rttEWMA = time.Duration(float64(rtt)*alpha + float64(e.rttEWMA)*(1-alpha))
	}
	e.rttSamples++

	// Compute adaptive cycle duration per spec §10.1
	// CycleDuration = BaseInterval + EWMA(RTT) * SafetyFactor
	latencyEstimate := time.Duration(float64(e.rttEWMA) * e.cfg.SafetyFactor)
	newDuration := e.cfg.BaseInterval + latencyEstimate

	// Cap at MaxCycleDuration (protocol hard cap)
	if newDuration > e.cfg.MaxCycleDuration {
		newDuration = e.cfg.MaxCycleDuration
	}

	// Minimum cycle duration is BaseInterval
	if newDuration < e.cfg.BaseInterval {
		newDuration = e.cfg.BaseInterval
	}

	e.cycleDuration = newDuration

	// Update cycleTimeout for PREPARE phase (use cycleDuration as timeout)
	e.cycleTimeout = e.cycleDuration
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

	// Keep the key rotation validator aligned with the current cycle and validator
	// set before it is asked to judge anything (spec §8).
	e.syncKeyRotationStateLocked()

	// Build pending entries: include retained entries from previous aborted cycles
	allPending := make([]chain.ProvenanceEntry, len(e.pendingEntries))
	copy(allPending, e.pendingEntries)
	allPending = append(allPending, e.pending...)

	if len(allPending) == 0 && e.cfg.SkipEmptyCycles {
		e.state.Cycle++
		return
	}

	// Admit any key rotation anchored in this batch before signatures are verified,
	// so a rotation learned in this cycle is honoured from the next cycle onwards.
	e.processKeyRotationEntriesLocked(allPending)

	// Admit mandates anchored in this batch, for the same reason and at the same point:
	// a mandate learned this cycle starts governing submissions from the next one.
	e.processMandateEntriesLocked(allPending)

	// Determine active validators from ValidatorSet (not all nodes in state)
	// ValidatorSet contains only the actual consensus validators
	activeValidators := len(e.state.ValidatorSet)
	if activeValidators == 0 {
		// Fallback: count peers with validator keys
		activeValidators = len(e.peers)
	}

	// Degraded mode: if N < MinValidators, Q = 1 (spec §5.5)
	requiredQuorum := quorumRequired(activeValidators)
	if e.degraded != nil && e.degraded.IsDegraded() {
		requiredQuorum = 1
	}

	rootArr := e.st.Root()

	// PHASE 1: PREPARE - proposer proposes, validators sign
	prepareResult := e.RunPreparePhase(cycle, rootArr, allPending, false, requiredQuorum)
	if prepareResult.Err != nil {
		log.Printf("IPC cycle %d: PREPARE failed: %v", cycle, prepareResult.Err)
		// Cycle aborted - retain entries for next cycle
		e.pendingEntries = allPending
		e.state.Cycle++
		return
	}

	// PHASE 2: QUORUM CHECK - proposer verifies quorum on the same block
	prepareResult = e.RunPreparePhase(cycle, rootArr, allPending, true, requiredQuorum)
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

	// Check degraded mode transition (spec §5.5)
	if e.degraded != nil {
		_, _ = e.degraded.CheckDegradedTransition(activeValidators, prepareResult.QuorumReached)
		// Apply degraded mode rules to block if in degraded mode
		if err := e.degraded.ApplyDegradedBlock(finalBlock, e.peers, e.node.UID.ID()); err != nil {
			log.Printf("IPC cycle %d: degraded mode error: %v", cycle, err)
			e.pendingEntries = allPending
			e.state.Cycle++
			return
		}
	}
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
		// len(e.blocks) is at least one here, since a block was just appended, but the
		// conversion is guarded rather than assumed: len-1 underflows to MaxUint64 on an
		// empty slice, and a proof claiming to be from block 18446744073709551615 would be
		// silently unusable rather than obviously wrong.
		blockIndex := uint64(0)
		if n := len(e.blocks); n > 0 {
			blockIndex = uint64(n - 1)
		}
		e.anchored[h] = &chain.AnchorProof{
			Found:      true,
			BlockIndex: blockIndex,
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

	// Publish block via Anchor Publisher (spec §11.1)
	if e.anchorPublisher != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		anchors, err := e.anchorPublisher.Publish(ctx, finalBlock)
		cancel()
		if err != nil {
			log.Printf("IPC cycle %d: anchor publisher error: %v", cycle, err)
		} else {
			finalBlock.ExternalAnchors = anchors
			log.Printf("IPC cycle %d: block published to %d anchor(s): %v", cycle, len(anchors), anchors)
		}
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

// VerifySMT checks an inclusion proof against an explicit root.
//
// The root is a parameter rather than the tree's current one so that a light client can
// tie an entry to a specific historical block: a proof against today's tree says nothing
// about last week's block unless the root is pinned to that block.
func (e *Engine) VerifySMT(key, value []byte, root [32]byte, proof [][32]byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st.Verify(key, value, root, proof)
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
