package consensus

import (
	"context"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/smt"
)

func setupEngine() *Engine {
	uid := identity.NewUIDZero("subchain-test", true)
	node := Node{UID: *uid, Addr: "self"}
	eng := NewEngine(node, time.Hour)
	eng.Start()
	return eng
}

func TestRegisterSubChain(t *testing.T) {
	eng := setupEngine()
	defer eng.Stop()
	mgr := eng.SubChains()

	id, err := mgr.Register("wardex", eng.node.UID.RootID)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var zero chain.SubChainID
	if id == zero {
		t.Fatal("expected non-zero SubChainID")
	}

	desc, err := mgr.Descriptor(id)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if desc.Name != "wardex" {
		t.Fatalf("expected name wardex, got %s", desc.Name)
	}
	if !desc.Active {
		t.Fatal("expected active sub-chain")
	}

	// Same human-readable name creates a different ID (different timestamp)
	id2, err := mgr.Register("wardex", eng.node.UID.RootID)
	if err != nil {
		t.Fatalf("second register should succeed with different ID: %v", err)
	}
	if id == id2 {
		t.Fatal("expected different SubChainID for same name (different timestamp)")
	}
}

func TestSubmitAndAnchor(t *testing.T) {
	eng := setupEngine()
	defer eng.Stop()
	mgr := eng.SubChains()

	id, _ := mgr.Register("anti-ransomware", eng.node.UID.RootID)

	entry := chain.ProvenanceEntry{
		Hash:      [32]byte{1, 2, 3},
		Submitter: eng.node.UID.RootID,
		Timestamp: time.Now().UnixNano(),
		Label:     "test-entry",
	}
	if err := mgr.Submit(id, entry); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if err := mgr.Anchor(id); err != nil {
		t.Fatalf("anchor: %v", err)
	}

	eng.RunCycle()
}

func TestCrossChainProof(t *testing.T) {
	eng := setupEngine()
	defer eng.Stop()
	mgr := eng.SubChains()

	id, _ := mgr.Register("wardex", eng.node.UID.RootID)

	entry := chain.ProvenanceEntry{
		Hash:      [32]byte{0xaa, 0xbb},
		Submitter: eng.node.UID.RootID,
		Timestamp: time.Now().UnixNano(),
		Label:     "cross-chain-test",
	}
	mgr.Submit(id, entry)
	mgr.Anchor(id)

	eng.RunCycle()

	subSt := smt.New(256)
	subSt.Insert(entry.Hash[:], entry.Hash[:])
	expectedRoot := subSt.Root()

	anchorData := append(id[:], expectedRoot[:]...)
	var anchorHash [32]byte
	copy(anchorHash[:], identity.Hash(anchorData))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := eng.WaitForAnchor(ctx, anchorHash)
	if err != nil {
		t.Fatalf("anchor not committed: %v", err)
	}

	proof, err := mgr.Prove(id, entry.Hash)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	if proof.EntryHash != entry.Hash {
		t.Fatal("EntryHash mismatch")
	}

	parentRoot := [32]byte{}
	copy(parentRoot[:], eng.GetStateRoot())
	if !mgr.VerifyCrossChain(proof, parentRoot) {
		t.Fatal("CrossChainProof verification failed")
	}

	badProof := *proof
	badProof.EntryHash[0] ^= 0xff
	if mgr.VerifyCrossChain(&badProof, parentRoot) {
		t.Fatal("tampered proof should not verify")
	}
}

func TestMultipleSubChains(t *testing.T) {
	eng := setupEngine()
	defer eng.Stop()
	mgr := eng.SubChains()

	wardex, _ := mgr.Register("wardex", eng.node.UID.RootID)
	ransom, _ := mgr.Register("anti-ransomware", eng.node.UID.RootID)

	wardexEntry1 := chain.ProvenanceEntry{Hash: [32]byte{1}}
	wardexEntry2 := chain.ProvenanceEntry{Hash: [32]byte{3}}
	ransomEntry := chain.ProvenanceEntry{Hash: [32]byte{2}}

	mgr.Submit(wardex, wardexEntry1)
	mgr.Submit(ransom, ransomEntry)
	mgr.Submit(wardex, wardexEntry2)

	mgr.Anchor(wardex)
	mgr.Anchor(ransom)

	eng.RunCycle()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// wardex has two entries
	subSt := smt.New(256)
	subSt.Insert(wardexEntry1.Hash[:], wardexEntry1.Hash[:])
	subSt.Insert(wardexEntry2.Hash[:], wardexEntry2.Hash[:])
	wardexRoot := subSt.Root()
	anchorData := append(wardex[:], wardexRoot[:]...)
	var wAnchor [32]byte
	copy(wAnchor[:], identity.Hash(anchorData))

	_, err := eng.WaitForAnchor(ctx, wAnchor)
	if err != nil {
		t.Fatalf("wardex anchor not committed: %v", err)
	}

	// ransom has one entry
	subSt2 := smt.New(256)
	subSt2.Insert(ransomEntry.Hash[:], ransomEntry.Hash[:])
	ransomRoot := subSt2.Root()
	anchorData2 := append(ransom[:], ransomRoot[:]...)
	var rAnchor [32]byte
	copy(rAnchor[:], identity.Hash(anchorData2))

	_, err = eng.WaitForAnchor(ctx, rAnchor)
	if err != nil {
		t.Fatalf("ransom anchor not committed: %v", err)
	}
}

func TestProveBeforeAnchorFails(t *testing.T) {
	eng := setupEngine()
	defer eng.Stop()
	mgr := eng.SubChains()

	id, _ := mgr.Register("empty", eng.node.UID.RootID)
	mgr.Submit(id, chain.ProvenanceEntry{Hash: [32]byte{9}})

	_, err := mgr.Prove(id, [32]byte{9})
	if err == nil {
		t.Fatal("expected error proving unanchored sub-chain")
	}
}
