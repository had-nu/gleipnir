package consensus

import (
	"sync"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
)

// networkBus delays every message by one round trip, standing in for the socket hop
// between two containers.
//
// The MemoryBus hands a Publish to every other engine inside the same goroutine: one
// node calls PublishSig and the others see it before yielding, so nothing can happen in
// the gap. No test built on it can observe what a node does while the message it is
// waiting for is still in flight, and that gap is the entire subject here.
//
// A published item becomes visible to the next accessor once the delay has elapsed.
// A background pump keeps time advancing so an item published by a goroutine that is
// not currently inside an accessor still arrives.
type networkBus struct {
	inner *MemoryBus
	delay time.Duration

	mu      sync.Mutex
	entries []networkEntry
	blocks  []networkBlock
	finals  []networkBlock
	sigs    []networkSig
	proofs  []networkProof
}

type networkEntry struct {
	entry chain.ProvenanceEntry
	born  time.Time
}

type networkBlock struct {
	block      chain.Block
	proposerID string
	born       time.Time
}

type networkSig struct {
	sig  BlockSig
	born time.Time
}

type networkProof struct {
	proof VRFProofMsg
	born  time.Time
}

var traceBus func(string, ...any)

func newNetworkBus(delay time.Duration) *networkBus {
	return &networkBus{inner: NewMemoryBus(), delay: delay}
}

// deliver moves every item whose delay has elapsed into the inner bus.
//
// Called with the lock held so a concurrent Publish cannot interleave between the
// due-check and the drain.
func (b *networkBus) deliver(now time.Time) {
	ready := func(born time.Time) bool { return now.Sub(born) >= b.delay }

	var kept []networkEntry
	for _, e := range b.entries {
		if ready(e.born) {
			b.inner.Publish(e.entry)
			continue
		}
		kept = append(kept, e)
	}
	b.entries = kept

	keptBlocks := []networkBlock(nil)
	for _, blk := range b.blocks {
		if ready(blk.born) {
			b.inner.Propose(blk.block, blk.proposerID)
			continue
		}
		keptBlocks = append(keptBlocks, blk)
	}
	b.blocks = keptBlocks

	keptFinals := []networkBlock(nil)
	for _, f := range b.finals {
		if ready(f.born) {
			b.inner.PublishFinal(f.block, f.proposerID)
			continue
		}
		keptFinals = append(keptFinals, f)
	}
	b.finals = keptFinals

	keptSigs := []networkSig(nil)
	for _, s := range b.sigs {
		if ready(s.born) {
			b.inner.PublishSig(s.sig)
			continue
		}
		keptSigs = append(keptSigs, s)
	}
	b.sigs = keptSigs

	keptProofs := []networkProof(nil)
	for _, p := range b.proofs {
		if ready(p.born) {
			b.inner.PublishVRFProof(p.proof)
			continue
		}
		keptProofs = append(keptProofs, p)
	}
	b.proofs = keptProofs
}

func (b *networkBus) advance() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deliver(time.Now())
}

func (b *networkBus) Publish(entry chain.ProvenanceEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, networkEntry{entry: entry, born: time.Now()})
}

func (b *networkBus) Snapshot() []chain.ProvenanceEntry {
	b.advance()
	return b.inner.Snapshot()
}

func (b *networkBus) RemoveEntries(remove map[[32]byte]bool) { b.inner.RemoveEntries(remove) }

func (b *networkBus) Propose(block chain.Block, proposerID string) {
	if traceBus != nil {
		traceBus("Propose cycle=%d by=%s", block.Index, proposerID[:8])
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blocks = append(b.blocks, networkBlock{block: block, proposerID: proposerID, born: time.Now()})
}

func (b *networkBus) GetProposed(cycle uint64) *chain.Block {
	b.advance()
	p := b.inner.GetProposed(cycle)
	if traceBus != nil {
		traceBus("GetProposed cycle=%d -> %v", cycle, p != nil)
	}
	return p
}

func (b *networkBus) PublishFinal(block chain.Block, proposerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.finals = append(b.finals, networkBlock{block: block, proposerID: proposerID, born: time.Now()})
}

func (b *networkBus) GetFinal(cycle uint64) *chain.Block {
	b.advance()
	return b.inner.GetFinal(cycle)
}

func (b *networkBus) PublishSig(sig BlockSig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sigs = append(b.sigs, networkSig{sig: sig, born: time.Now()})
}

func (b *networkBus) GetSigs(cycle uint64) []BlockSig {
	b.advance()
	return b.inner.GetSigs(cycle)
}

func (b *networkBus) PublishVRFProof(proof VRFProofMsg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.proofs = append(b.proofs, networkProof{proof: proof, born: time.Now()})
}

func (b *networkBus) GetVRFProofs(cycle uint64) []VRFProofMsg {
	b.advance()
	return b.inner.GetVRFProofs(cycle)
}

// pump advances delivery on a timer until stop is closed, so a message published by a
// goroutine that is not currently inside an accessor still arrives.
func (b *networkBus) pump(stop <-chan struct{}) {
	tick := b.delay / 4
	if tick <= 0 {
		tick = time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			b.advance()
		}
	}
}

var _ GossipChannel = (*networkBus)(nil)
