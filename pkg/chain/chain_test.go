package chain

import (
	"crypto/sha256"
	"testing"
)

func TestProvenanceEntry(t *testing.T) {
	hash := sha256.Sum256([]byte("test-entry"))
	var submitter [16]byte
	copy(submitter[:], []byte("test-submitter"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: submitter,
		Timestamp: 1700000000,
		Label:     "test-label",
	}

	if entry.Hash != hash {
		t.Fatal("hash mismatch")
	}
	if entry.Submitter != submitter {
		t.Fatal("submitter mismatch")
	}
	if entry.Label != "test-label" {
		t.Fatal("label mismatch")
	}
}

func TestProvenanceEntryWithApprover(t *testing.T) {
	hash := sha256.Sum256([]byte("test-approver"))
	var submitter, approver [16]byte
	copy(submitter[:], []byte("submitter-uid"))
	copy(approver[:], []byte("approver-uid"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: submitter,
		Timestamp: 1700000000,
		Label:     "test-approver-label",
		Approver:  &approver,
	}

	if entry.Approver == nil || *entry.Approver != approver {
		t.Fatalf("expected approver %v, got %v", approver, entry.Approver)
	}
}

func TestProvenanceEntryWithReference(t *testing.T) {
	hash := sha256.Sum256([]byte("test-ref"))
	refHash := sha256.Sum256([]byte("related-entry"))
	var submitter [16]byte
	copy(submitter[:], []byte("submitter"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: submitter,
		Timestamp: 1700000000,
		Label:     "test-ref-label",
		Reference: &refHash,
	}

	if entry.Reference == nil {
		t.Fatal("reference is nil")
	}
	if *entry.Reference != refHash {
		t.Fatal("reference mismatch")
	}
}

func TestProvenanceEntryWithSignature(t *testing.T) {
	hash := sha256.Sum256([]byte("test-sig"))
	var submitter [16]byte
	copy(submitter[:], []byte("submitter"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: submitter,
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
	var submitter, approver [16]byte
	copy(submitter[:], []byte("submitter"))
	copy(approver[:], []byte("approver"))
	entry := ProvenanceEntry{
		Hash:      hash,
		Submitter: submitter,
		Timestamp: 1700000000,
		Label:     "all-fields",
		Approver:  &approver,
		Reference: &refHash,
		Signature: []byte("signature-data"),
	}

	if entry.Submitter != submitter {
		t.Fatal("submitter mismatch")
	}
	if entry.Approver == nil || *entry.Approver != approver {
		t.Fatal("approver mismatch")
	}
	if entry.Reference == nil || *entry.Reference != refHash {
		t.Fatal("reference mismatch")
	}
	if len(entry.Signature) == 0 {
		t.Fatal("signature missing")
	}
	if entry.Label != "all-fields" {
		t.Fatal("label mismatch")
	}
}

func TestBlockHash(t *testing.T) {
	var proposer [16]byte
	copy(proposer[:], []byte("proposer-uid"))
	block := &Block{
		Index:       1,
		PrevHash:    make([]byte, 32),
		StateRoot:   make([]byte, 32),
		Proposer:    proposer,
		Anchored:    []ProvenanceEntry{},
		Lambda1:     0.1,
		Timestamp:   1700000000,
		Quorum:      QuorumConfig{TotalValidators: 3, RequiredSigs: 2},
		Validators:  []ValidatorInfo{},
		PrepareSigs: [][]byte{},
	}

	hash1 := ComputeBlockHash(block)
	if len(hash1) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(hash1))
	}
	hash2 := ComputeBlockHash(block)
	if string(hash1) != string(hash2) {
		t.Fatal("block hash is not deterministic")
	}
}