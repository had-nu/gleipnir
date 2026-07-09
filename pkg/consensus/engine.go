// IPC consensus engine. Gleipnir is the reference implementation.
package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
}

func NewEngine(node Node, cycleInterval time.Duration) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		node:          node,
		state:         state.NetworkState{Cycle: 0, Nodes: make(map[string]state.NodeState), Graph: state.ReputationGraph{}},
		cfg:           state.DefaultConfig,
		st:            smt.New(256),
		blocks:        make([]chain.Block, 0),
		pending:       make([]chain.ProvenanceEntry, 0),
		anchored:      make(map[[32]byte]*chain.AnchorProof),
		cycleInterval: cycleInterval,
		ctx:           ctx,
		cancel:        cancel,
	}
}

func (e *Engine) Start() {
	go e.cycleLoop()
	log.Printf("IPC engine started, cycle interval=%v", e.cycleInterval)
}

func (e *Engine) Stop() {
	e.cancel()
}

func (e *Engine) Submit(entry chain.ProvenanceEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending = append(e.pending, entry)
}

func (e *Engine) VerifyHash(hash [32]byte) (*chain.AnchorProof, bool) {
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

func (e *Engine) GetStateRoot() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.st.Root()
	return r[:]
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
			e.runCycle()
		}
	}
}

func (e *Engine) runCycle() {
	e.mu.Lock()
	defer e.mu.Unlock()

	cycle := e.state.Cycle

	if len(e.pending) == 0 {
		e.state.Cycle++
		return
	}

	entries := make([]chain.ProvenanceEntry, len(e.pending))
	copy(entries, e.pending)
	e.pending = e.pending[:0]

	rootArr := e.st.Root()
	proposer, _ := SelectProposer(
		[]Peer{{UID: e.node.UID, Addr: e.node.Addr, Alive: true}},
		cycle,
		rootArr[:],
	)

	prevHash := make([]byte, 32)
	if len(e.blocks) > 0 {
		prevHash = e.blocks[len(e.blocks)-1].BlockHash
	}

	block := chain.Block{
		Index:     cycle,
		PrevHash:  prevHash,
		Proposer:  proposer.UID.RootID,
		Anchored:  entries,
		Lambda1:   e.state.Lambda1,
		Timestamp: time.Now().UnixNano(),
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
			BlockIndex: cycle,
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
	block.Sigs[0] = identity.SignDilithium(e.node.UID.SecretKey, blockHash)

	next, err := state.Apply(e.state, e.state.StateRoot, []string{hex.EncodeToString(e.node.UID.RootID)}, e.cfg)
	if err != nil {
		log.Printf("IPC cycle %d: state apply error: %v", cycle, err)
		return
	}
	e.state = next
	e.blocks = append(e.blocks, block)

	log.Printf("IPC cycle %d: block anchored with %d entries, root=%x, λ₁=%.4f",
		cycle, len(entries), block.StateRoot, e.state.Lambda1)
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
