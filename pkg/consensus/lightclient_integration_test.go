// Light client verification against blocks this engine actually produced.
//
// The unit tests in pkg/lightclient build blocks by hand, which proves the verifier is
// self-consistent. It does not prove the verifier agrees with the consensus engine about
// what a block looks like -- and the two have to agree exactly, since the pairing of
// PrepareSigsPayload with PrepareSigsBitmap is the sort of thing that reads two ways.
//
// This test lives in package consensus rather than lightclient so it can reuse the
// multi-node fixtures and configure the engine's unexported config. That does not create
// an import cycle: pkg/lightclient does not import pkg/consensus, it depends on the
// BlockSource interface.
package consensus

import (
	"errors"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/lightclient"
)

// lightClientFixture is a live three-validator network plus the validator set a light
// client would obtain from genesis.
type lightClientFixture struct {
	engines    []*Engine
	engine     *Engine
	bus        *MemoryBus
	peers      []Peer
	validators []chain.ValidatorInfo
}

func newLightClientFixture(t *testing.T) *lightClientFixture {
	t.Helper()

	peers, nodes := makePeersAndNodes("lc-0", "lc-1", "lc-2")
	bus := NewMemoryBus()

	engines := make([]*Engine, 3)
	for i := range engines {
		engines[i] = NewEngineWithPeers(nodes[i], time.Hour, bus, peers)
		engines[i].cfg.SkipEmptyCycles = false
		// A fresh network has λ₁ = 0, which is below the default threshold.
		engines[i].cfg.MinLambda1 = 0.001
	}

	validators := make([]chain.ValidatorInfo, 0, len(peers))
	for _, p := range peers {
		validators = append(validators, chain.ValidatorInfo{
			ValidatorID:  p.UID.RootID,
			Dilithium3PK: p.UID.PublicKey,
			VRFPK:        p.UID.VRFPublicKey,
			ContractHash: p.UID.ContractHash,
		})
	}

	f := &lightClientFixture{engines: engines, engine: engines[0], bus: bus, peers: peers, validators: validators}
	f.seedVRF(t, 0)
	return f
}

// seedVRF publishes every peer's VRF proof for a cycle.
//
// Proposer selection needs a proof from every peer, and in production those arrive over
// gossip while the cycle is in flight. Seeding them removes a scheduling race so the
// assertions measure consensus behaviour.
func (f *lightClientFixture) seedVRF(t *testing.T, cycle uint64) {
	var root [32]byte
	if cycle > 0 {
		f.engine.mu.Lock()
		root = f.engine.st.Root()
		f.engine.mu.Unlock()
	}
	seedVRFProofs(t, f.bus, f.peers, cycle, root)
}

// runCycles runs n cycles, seeding VRF proofs and submitting a fresh entry from each
// validator before every one of them.
//
// The fresh entries matter. SkipEmptyCycles is off so cycles run regardless, but a cycle
// with nothing to anchor is signed only by the proposer, so it cannot reach PREPARE
// quorum. A block with a single signature would make the verification assertions pass
// vacuously or fail for the wrong reason.
func (f *lightClientFixture) runCycles(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		f.submitEntries(t, byte(200+i*len(f.peers)))
		f.seedVRF(t, uint64(i))
		runCyclesConcurrently(f.engines)
	}
}

// submitEntries enqueues one distinct entry per validator, so a cycle has content to
// anchor and a quorum of distinct signers.
func (f *lightClientFixture) submitEntries(t *testing.T, salt byte) {
	t.Helper()
	for i, p := range f.peers {
		var hash [32]byte
		for j := range hash {
			hash[j] = salt + byte(i) + byte(j)
		}
		if err := f.engine.Enqueue(chain.ProvenanceEntry{
			Hash: hash, Submitter: p.UID.RootID,
			Timestamp: time.Now().UnixNano(), Label: "light-client-fixture",
		}); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
}

// lastBlock returns the most recent block the engine produced.
func (f *lightClientFixture) lastBlock(t *testing.T) *chain.Block {
	t.Helper()
	count := f.engine.BlockCount()
	if count == 0 {
		t.Fatal("the engine produced no blocks")
	}
	block := f.engine.GetBlock(count - 1)
	if block == nil {
		t.Fatalf("no block at position %d", count-1)
	}
	return block
}

// anchorAfter returns the trust anchor a light client holds having verified the block
// before the one given.
func (f *lightClientFixture) anchorBefore(block *chain.Block) lightclient.TrustAnchor {
	anchor := lightclient.TrustAnchor{BlockIndex: block.Index - 1, Validators: f.validators}
	if block.Index > 0 {
		if prev := f.engine.GetBlock(block.Index - 1); prev != nil {
			anchor.BlockHash = prev.BlockHash
		}
	}
	return anchor
}

// TestLightClientVerifiesEngineProducedBlock is the loop-closing test.
//
// The verifier was written against §5.3's description of PrepareSigsPayload as a
// compacted, bitmap-ordered list. If that reading were wrong, a block the entire network
// accepted would fail here. It passing is the evidence that the light client and the
// consensus engine read the same wire format.
func TestLightClientVerifiesEngineProducedBlock(t *testing.T) {
	f := newLightClientFixture(t)

	// Several cycles, because the first one cannot reach PREPARE quorum: the VRF proofs
	// for the cycle in flight have not propagated yet, so only the elected proposer's own
	// signature is present.
	f.runCycles(t, 4)

	block := f.lastBlock(t)

	// Preconditions, or the assertions below would pass vacuously.
	if len(block.PrepareSigs) < 1 {
		t.Fatal("the engine produced a block with no PREPARE signatures")
	}
	if len(block.PrepareSigsBitmap) == 0 {
		t.Fatal("the engine produced a block with no PREPARE bitmap")
	}
	if block.ProtocolVersion != 2 {
		t.Fatalf("the engine produced a ProtocolVersion %d block", block.ProtocolVersion)
	}
	if len(block.CommitSig) != identity.Dilithium3SignatureSize {
		t.Fatalf("the engine produced a %d-byte COMMIT signature, want %d",
			len(block.CommitSig), identity.Dilithium3SignatureSize)
	}

	// Three validators is below §6.5's threshold, so the chain is degraded and the engine
	// both lowers the quorum to one and announces the mode. Both halves are asserted, since
	// a verifier that got the degraded rule wrong in either direction would still pass the
	// VerifyBlock call below on a differently-configured chain.
	if len(f.validators) >= lightclient.DegradedThreshold {
		t.Fatalf("the fixture has %d validators, so it is not degraded; the degraded "+
			"assertions below would not apply", len(f.validators))
	}
	if string(block.Metadata[lightclient.DegradedLabel]) != "true" {
		t.Fatalf("a degraded block carries no %s marker: %v",
			lightclient.DegradedLabel, block.Metadata)
	}

	svc := lightclient.New(f.engine, f.engine)
	if err := svc.VerifyBlock(block, f.anchorBefore(block)); err != nil {
		t.Fatalf("the light client rejected a block the engine produced and accepted: %v", err)
	}
}

// TestLightClientVerifiesWholeProducedChain verifies every block in turn, each against
// the previous one, which is how a client would actually walk a chain.
func TestLightClientVerifiesWholeProducedChain(t *testing.T) {
	f := newLightClientFixture(t)

	f.runCycles(t, 4)

	svc := lightclient.New(f.engine, f.engine)
	verified := 0
	for i := uint64(0); i < f.engine.BlockCount(); i++ {
		block := f.engine.GetBlock(i)
		if block == nil {
			continue
		}
		if err := svc.VerifyBlock(block, f.anchorBefore(block)); err != nil {
			t.Fatalf("block %d of the produced chain was rejected: %v", i, err)
		}
		verified++
	}
	if verified == 0 {
		t.Fatal("no blocks were verified")
	}
}

// TestLightClientBitmapMatchesPayloadDensity records the relationship the tests above lean
// on: the engine emits a compacted payload, so the number of signatures equals the number
// of set bits rather than the validator count. If the engine ever switched to positional
// signatures, this fails before the verifier's assumption could become a silent
// interoperability break.
func TestLightClientBitmapMatchesPayloadDensity(t *testing.T) {
	f := newLightClientFixture(t)

	f.runCycles(t, 4)

	block := f.lastBlock(t)
	bits := 0
	for _, b := range block.PrepareSigsBitmap {
		for i := 0; i < 8; i++ {
			if b&(1<<i) != 0 {
				bits++
			}
		}
	}
	if bits != len(block.PrepareSigs) {
		t.Fatalf("bitmap marks %d signers but the payload holds %d signatures; §5.3 says "+
			"the payload is compacted to the signers only", bits, len(block.PrepareSigs))
	}
	if len(block.PrepareSigs) >= len(f.validators) {
		t.Skip("every validator signed, so a compacted payload is indistinguishable from a positional one")
	}
}

// TestLightClientRejectsTamperedEngineBlock confirms the verifier is not simply waving
// engine output through.
func TestLightClientRejectsTamperedEngineBlock(t *testing.T) {
	f := newLightClientFixture(t)

	f.runCycles(t, 4)

	real := f.lastBlock(t)

	// Copy and edit, so the engine's own block is untouched.
	tampered := *real
	tampered.Anchored = append(append([]chain.ProvenanceEntry(nil), real.Anchored...),
		chain.ProvenanceEntry{Hash: [32]byte{0xEE}, Timestamp: 1, Label: "injected"})

	svc := lightclient.New(f.engine, f.engine)
	err := svc.VerifyBlock(&tampered, f.anchorBefore(real))
	if err == nil {
		t.Fatal("a tampered copy of an engine-produced block verified")
	}
	if !errors.Is(err, lightclient.ErrBlockHashMismatch) {
		t.Errorf("got %v, want ErrBlockHashMismatch", err)
	}
}

// TestLightClientRejectsStaleChainBlock checks the PrevHash and index rules against real
// blocks: a genuine block that does not follow the anchor must not verify.
func TestLightClientRejectsStaleChainBlock(t *testing.T) {
	f := newLightClientFixture(t)

	f.runCycles(t, 4)

	block := f.lastBlock(t)

	// An anchor at a different index cannot verify this block, however genuine it is.
	wrongAnchor := f.anchorBefore(block)
	wrongAnchor.BlockHash = make([]byte, 32)
	wrongAnchor.BlockIndex = block.Index + 5

	svc := lightclient.New(f.engine, f.engine)
	err := svc.VerifyBlock(block, wrongAnchor)
	if err == nil {
		t.Fatal("a genuine block verified against an anchor it does not follow")
	}
	if !errors.Is(err, lightclient.ErrChainBreak) {
		t.Errorf("got %v, want ErrChainBreak", err)
	}
}

// TestLightClientRejectsForgedSignerOnRealBlock takes a real block and replaces one PREPARE
// signature with one from a key outside the validator set. The block hash is untouched, so
// only per-signature verification can catch it.
func TestLightClientRejectsForgedSignerOnRealBlock(t *testing.T) {
	f := newLightClientFixture(t)

	f.runCycles(t, 4)

	block := f.lastBlock(t)
	if len(block.PrepareSigs) < 1 {
		t.Fatal("the engine produced a block with no PREPARE signatures")
	}

	// A key that is not any validator's.
	foreign := make([]byte, identity.Dilithium3SeedSize)
	for i := range foreign {
		foreign[i] = byte(200 + i)
	}
	_, foreignSK, err := identity.GenerateDilithiumKeyFromSeed(foreign)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// One genuine signature plus one forged one, both marked in the bitmap.
	//
	// Replacing the genuine signature instead of adding to it would not test what it looks
	// like: the fixture is degraded, so quorum is one, and zero valid signatures would fail
	// the quorum count before any per-signature check ran. Keeping the genuine signature
	// means the quorum is satisfied and the forged one is what fails.
	forged := *block
	forged.PrepareSigsBitmap = append([]byte(nil), block.PrepareSigsBitmap...)
	forged.PrepareSigs = append([][]byte(nil), block.PrepareSigs...)

	// Claim one more signer: the first validator whose bit is not already set. The engine
	// marks the validator that actually signed, which is not necessarily the lowest index,
	// so the free bit has to be searched for rather than derived from the payload length.
	free := -1
	for i := 0; i < len(block.Validators)*8 && free < 0; i++ {
		if i/8 >= len(forged.PrepareSigsBitmap) {
			forged.PrepareSigsBitmap = append(forged.PrepareSigsBitmap, 0)
		}
		if forged.PrepareSigsBitmap[i/8]&(1<<(i%8)) == 0 {
			free = i
		}
	}
	if free < 0 {
		t.Fatalf("every validator bit is already set in %x", forged.PrepareSigsBitmap)
	}
	forged.PrepareSigsBitmap[free/8] |= 1 << (free % 8)
	forged.PrepareSigs = append(forged.PrepareSigs, identity.SignDilithium(foreignSK, block.BlockHash))

	svc := lightclient.New(f.engine, f.engine)
	err = svc.VerifyBlock(&forged, f.anchorBefore(block))
	if err == nil {
		t.Fatal("a real block with one forged signature verified")
	}
	if !errors.Is(err, lightclient.ErrBadSignature) {
		t.Errorf("got %v, want ErrBadSignature", err)
	}
}

// TestLightClientRejectsForgedCommitOnRealBlock covers the proposer's signature
// specifically: a genuine PREPARE quorum with a COMMIT signature from outside the set.
func TestLightClientRejectsForgedCommitOnRealBlock(t *testing.T) {
	f := newLightClientFixture(t)

	f.runCycles(t, 4)

	block := f.lastBlock(t)

	foreign := make([]byte, identity.Dilithium3SeedSize)
	for i := range foreign {
		foreign[i] = byte(210 + i)
	}
	_, foreignSK, err := identity.GenerateDilithiumKeyFromSeed(foreign)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	forged := *block
	forged.CommitSig = identity.SignDilithium(foreignSK, block.BlockHash)

	svc := lightclient.New(f.engine, f.engine)
	err = svc.VerifyBlock(&forged, f.anchorBefore(block))
	if err == nil {
		t.Fatal("a real block with a forged COMMIT signature verified")
	}
	if !errors.Is(err, lightclient.ErrBadSignature) {
		t.Errorf("got %v, want ErrBadSignature", err)
	}
}
