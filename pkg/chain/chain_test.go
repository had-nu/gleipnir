package chain

import (
	"crypto/sha256"
	"testing"
)

func TestProvenanceEntry(t *testing.T) {
	hash := sha256.Sum256([]byte("test-entry"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: []byte("test-submitter"),
		Timestamp: 1700000000,
		Label:     "test-label",
	}

	if entry.Hash != hash {
		t.Fatal("hash mismatch")
	}
	if string(entry.Submitter) != "test-submitter" {
		t.Fatal("submitter mismatch")
	}
	if entry.Label != "test-label" {
		t.Fatal("label mismatch")
	}
}

func TestProvenanceEntryWithApprover(t *testing.T) {
	hash := sha256.Sum256([]byte("test-approver"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: []byte("submitter-uid"),
		Timestamp: 1700000000,
		Label:     "test-approver-label",
		Approver:  []byte("approver-uid"),
	}

	if string(entry.Approver) != "approver-uid" {
		t.Fatalf("expected approver approver-uid, got %s", string(entry.Approver))
	}
}

func TestProvenanceEntryWithReference(t *testing.T) {
	hash := sha256.Sum256([]byte("test-ref"))
	refHash := sha256.Sum256([]byte("related-entry"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: []byte("submitter"),
		Timestamp: 1700000000,
		Label:     "test-ref-label",
		Reference: refHash[:],
	}

	if len(entry.Reference) != 32 {
		t.Fatalf("expected reference to be 32 bytes, got %d", len(entry.Reference))
	}
}

func TestProvenanceEntryWithSignature(t *testing.T) {
	hash := sha256.Sum256([]byte("test-sig"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: []byte("submitter"),
		Timestamp: 1700000000,
		Label:     "test-sig-label",
		Signature: []byte("dilithium3-signature-bytes"),
	}

	if len(entry.Signature) == 0 {
		t.Fatal("signature should not be empty")
	}
}

func TestProvenanceEntryAllFields(t *testing.T) {
	hash := sha256.Sum256([]byte("test-all-fields"))
	refHash := sha256.Sum256([]byte("related"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: []byte("submitter"),
		Timestamp: 1700000000,
		Label:     "all-fields",
		Approver:  []byte("approver"),
		Reference: refHash[:],
		Signature: []byte("signature-data"),
	}

	if string(entry.Submitter) != "submitter" {
		t.Fatal("submitter mismatch")
	}
	if string(entry.Approver) != "approver" {
		t.Fatal("approver mismatch")
	}
	if len(entry.Reference) != 32 {
		t.Fatal("reference mismatch")
	}
	if len(entry.Signature) == 0 {
		t.Fatal("signature missing")
	}
	if entry.Label != "all-fields" {
		t.Fatal("label mismatch")
	}
}

func TestBlockBasic(t *testing.T) {
	hash := sha256.Sum256([]byte("entry"))
	block := Block{
		Index:     1,
		PrevHash:  make([]byte, 32),
		Proposer:  []byte("proposer"),
		Anchored:  []ProvenanceEntry{{Hash: hash, Submitter: []byte("s"), Timestamp: 1, Label: "l"}},
		Lambda1:   0.5,
		Timestamp: 1700000000,
	}

	if block.Index != 1 {
		t.Fatalf("expected index 1, got %d", block.Index)
	}
	if len(block.Anchored) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(block.Anchored))
	}
	if block.Anchored[0].Label != "l" {
		t.Fatal("entry label mismatch")
	}
}

func TestAnchorProof(t *testing.T) {
	proof := &AnchorProof{
		Found:      true,
		BlockIndex: 1,
		BlockTime:  1700000000,
		StateRoot:  []byte("root"),
		SMTProof:   []byte("proof"),
		Submitter:  []byte("submitter"),
		Label:      "test",
	}

	if !proof.Found {
		t.Fatal("proof should be found")
	}
	if proof.BlockIndex != 1 {
		t.Fatal("block index mismatch")
	}
}

func TestNetworkHealth(t *testing.T) {
	h := NetworkHealth{
		Lambda1:       0.42,
		ActivePeers:   3,
		TotalPeers:    5,
		BlockHeight:   100,
		PendingHashes: 7,
		AvgTPS:        1.5,
	}

	if h.ActivePeers != 3 || h.TotalPeers != 5 {
		t.Fatal("peer counts mismatch")
	}
	if h.BlockHeight != 100 {
		t.Fatal("height mismatch")
	}
}

func TestTicket(t *testing.T) {
	ticket := Ticket{
		Hash:       [32]byte{1, 2, 3},
		Status:     "pending",
		BlockIndex: 42,
		BlockTime:  1700000000,
	}

	if ticket.Status != "pending" {
		t.Fatal("status mismatch")
	}
}
