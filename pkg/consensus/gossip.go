package consensus

import (
	"sync"

	"github.com/had-nu/gleipnir/pkg/chain"
)

type GossipChannel interface {
	Publish(entry chain.ProvenanceEntry)
	Snapshot() []chain.ProvenanceEntry
	RemoveEntries(remove map[[32]byte]bool)
	Propose(block chain.Block, proposerID string)
	GetProposed(cycle uint64) *chain.Block
	PublishSig(sig BlockSig)
	GetSigs(cycle uint64) []BlockSig
	PublishVRFProof(proof VRFProofMsg)
	GetVRFProofs(cycle uint64) []VRFProofMsg
}

type BlockSig struct {
	Cycle    uint64
	Sig      []byte
	SignerID string
}

type VRFProofMsg struct {
	Cycle    uint64
	Proof    []byte // serialized VRFProof
	SignerID string
}

type MemoryBus struct {
	mu         sync.Mutex
	entries    []chain.ProvenanceEntry
	proposals  map[uint64]*chain.Block
	sigs       map[uint64][]BlockSig
	vrfProofs  map[uint64][]VRFProofMsg
}

func NewMemoryBus() *MemoryBus {
	return &MemoryBus{
		entries:   make([]chain.ProvenanceEntry, 0),
		proposals: make(map[uint64]*chain.Block),
		sigs:      make(map[uint64][]BlockSig),
		vrfProofs: make(map[uint64][]VRFProofMsg),
	}
}

func (b *MemoryBus) Publish(entry chain.ProvenanceEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, entry)
}

func (b *MemoryBus) Snapshot() []chain.ProvenanceEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]chain.ProvenanceEntry, len(b.entries))
	copy(out, b.entries)
	return out
}

func (b *MemoryBus) RemoveEntries(remove map[[32]byte]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	kept := make([]chain.ProvenanceEntry, 0, len(b.entries))
	for _, e := range b.entries {
		if !remove[e.Hash] {
			kept = append(kept, e)
		}
	}
	b.entries = kept
}

func (b *MemoryBus) Propose(block chain.Block, proposerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.proposals[block.Index]; !exists {
		cp := block
		b.proposals[block.Index] = &cp
	}
}

func (b *MemoryBus) GetProposed(cycle uint64) *chain.Block {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.proposals[cycle]
	if !ok {
		return nil
	}
	cp := *p
	return &cp
}

func (b *MemoryBus) PublishSig(sig BlockSig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, existing := range b.sigs[sig.Cycle] {
		if existing.SignerID == sig.SignerID {
			return
		}
	}
	b.sigs[sig.Cycle] = append(b.sigs[sig.Cycle], sig)
}

func (b *MemoryBus) GetSigs(cycle uint64) []BlockSig {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]BlockSig, len(b.sigs[cycle]))
	copy(out, b.sigs[cycle])
	return out
}

func (b *MemoryBus) PublishVRFProof(proof VRFProofMsg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, existing := range b.vrfProofs[proof.Cycle] {
		if existing.SignerID == proof.SignerID {
			return
		}
	}
	b.vrfProofs[proof.Cycle] = append(b.vrfProofs[proof.Cycle], proof)
}

func (b *MemoryBus) GetVRFProofs(cycle uint64) []VRFProofMsg {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]VRFProofMsg, len(b.vrfProofs[cycle]))
	copy(out, b.vrfProofs[cycle])
	return out
}
