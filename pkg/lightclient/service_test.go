// Light client verification tests — 3CP v2.0 §12.2 and
// notes/light-client-verification.md.
//
// The property under test throughout is that a light client trusts nothing the block
// says about itself. Each adversarial case below is a block that would verify if any
// single check were skipped.
package lightclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

// validator is a test validator with its key material.
type validator struct {
	info chain.ValidatorInfo
	sk   []byte
}

// newValidators builds n validators. idBase and seedBase are separate so a second,
// unrelated set can have different keys *and* different RootIDs: reusing the same
// identities would make a key-comparison test pass for the wrong reason.
func newValidators(t *testing.T, n int, idBase, seedBase byte) []validator {
	t.Helper()

	out := make([]validator, 0, n)
	for i := 0; i < n; i++ {
		seed := make([]byte, identity.Dilithium3SeedSize)
		for j := range seed {
			seed[j] = seedBase + byte(i) + byte(j)
		}
		pk, sk, err := identity.GenerateDilithiumKeyFromSeed(seed)
		if err != nil {
			t.Fatalf("keygen for validator %d: %v", i, err)
		}
		out = append(out, validator{
			info: chain.ValidatorInfo{
				ValidatorID:  [16]byte{idBase + byte(i)},
				Dilithium3PK: pk,
				VRFPK:        [32]byte{idBase + byte(i)},
				ContractHash: [32]byte{idBase + byte(i) + 100},
			},
			sk: sk,
		})
	}
	return out
}

func infos(vs []validator) []chain.ValidatorInfo {
	out := make([]chain.ValidatorInfo, len(vs))
	for i := range vs {
		out[i] = vs[i].info
	}
	return out
}

// blockSpec describes the block to build, so a test can vary one thing.
type blockSpec struct {
	index      uint64
	prevHash   []byte
	proposer   int
	signers    []int
	validators []chain.ValidatorInfo
	timestamp  int64

	// proposerID and proposerSK override the proposer identity and its signing key. Both
	// are needed because Proposer is covered by the block hash, so a block with a stranger
	// as proposer must be built that way from the start rather than patched afterwards.
	proposerID [16]byte
	proposerSK []byte
}

// buildBlock assembles a block and signs it properly: the hash is computed from the
// contents first, then each named signer's signature goes into PrepareSigsPayload, with
// the bitmap marking exactly those positions.
func buildBlock(t *testing.T, spec blockSpec, vs []validator) *chain.Block {
	t.Helper()

	if spec.timestamp == 0 {
		spec.timestamp = 1700000000000000000
	}
	proposerID := vs[spec.proposer].info.ValidatorID
	proposerSK := vs[spec.proposer].sk
	if spec.proposerID != ([16]byte{}) {
		proposerID = spec.proposerID
	}
	if spec.proposerSK != nil {
		proposerSK = spec.proposerSK
	}

	b := &chain.Block{
		Index:             spec.index,
		PrevHash:          spec.prevHash,
		StateRoot:         make([]byte, 32),
		Proposer:          proposerID,
		Anchored:          []chain.ProvenanceEntry{},
		Timestamp:         spec.timestamp,
		Quorum:            chain.QuorumConfig{TotalValidators: len(vs), RequiredSigs: requiredQuorum(len(vs))},
		ProtocolVersion:   2,
		Validators:        spec.validators,
		PrepareSigsBitmap: make([]byte, (len(vs)+7)/8),
		KeyRotationEpoch:  0,
	}
	b.BlockHash = chain.ComputeBlockHash(b)

	// One signature per named signer, in ascending validator order, matching the bitmap
	// layout the engine uses.
	signers := append([]int(nil), spec.signers...)
	for i := 1; i < len(signers); i++ {
		for j := i; j > 0 && signers[j] < signers[j-1]; j-- {
			signers[j], signers[j-1] = signers[j-1], signers[j]
		}
	}
	for _, idx := range signers {
		b.PrepareSigsBitmap[idx/8] |= 1 << (idx % 8)
		b.PrepareSigs = append(b.PrepareSigs,
			identity.SignDilithium(vs[idx].sk, b.BlockHash))
	}
	b.CommitSig = identity.SignDilithium(proposerSK, b.BlockHash)
	return b
}

// source is an in-memory BlockSource.
type source struct {
	blocks []*chain.Block
}

func (s *source) GetBlock(index uint64) *chain.Block {
	if index >= uint64(len(s.blocks)) {
		return nil
	}
	return s.blocks[index]
}

func (s *source) BlockCount() uint64 { return uint64(len(s.blocks)) }

// anchorAt builds a trust anchor positioned so that the next block has the given index.
func anchorAt(validators []chain.ValidatorInfo, index uint64, blockHash []byte) TrustAnchor {
	return TrustAnchor{BlockIndex: index, BlockHash: blockHash, Validators: validators}
}

// TestVerifyBlockAcceptsHonestChain is the happy path.
func TestVerifyBlockAcceptsHonestChain(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)

	anchor := anchorAt(info, 0, make([]byte, 32))
	block := buildBlock(t, blockSpec{
		index:      1,
		prevHash:   anchor.BlockHash,
		proposer:   0,
		signers:    []int{0, 1, 2},
		validators: info,
	}, vs)

	svc := New(&source{blocks: []*chain.Block{block}}, nil)
	if err := svc.VerifyBlock(block, anchor); err != nil {
		t.Fatalf("an honestly signed block was rejected: %v", err)
	}
}

// TestVerifyBlockRejectsSelfDeclaredValidators is the central property.
//
// A block names its own validator set. If the verifier read the set from the block, a
// writer could publish a block listing only validators it controls, sign it with their
// own keys, and satisfy every check: the quorum would be counted against its own list and
// the proposer's key would be one it chose. Here the same block is verified against the
// honest set it does not control, and must be rejected.
func TestVerifyBlockRejectsSelfDeclaredValidators(t *testing.T) {
	honest := newValidators(t, 4, 1, 10)
	attackers := newValidators(t, 4, 91, 90)

	// The attacker builds a chain of its own: it proposes, it signs, and it declares a
	// validator set made entirely of its own keys.
	attackerAnchor := anchorAt(infos(attackers), 0, make([]byte, 32))
	attackerBlock := buildBlock(t, blockSpec{
		index:      1,
		prevHash:   attackerAnchor.BlockHash,
		proposer:   0,
		signers:    []int{0, 1, 2},
		validators: infos(attackers),
	}, attackers)

	// It verifies against its own set, which is the flaw the design avoids.
	if err := New(nil, nil).VerifyBlock(attackerBlock, attackerAnchor); err != nil {
		t.Fatalf("test setup is wrong: the attacker's own chain should verify against its own set: %v", err)
	}

	// Against the real set it must not.
	honestAnchor := anchorAt(infos(honest), 0, make([]byte, 32))
	err := New(nil, nil).VerifyBlock(attackerBlock, honestAnchor)
	if err == nil {
		t.Fatal("a block naming an attacker-controlled validator set verified against the honest set")
	}
	if !errors.Is(err, ErrValidatorSetMismatch) {
		t.Errorf("got %v, want ErrValidatorSetMismatch", err)
	}
}

// TestVerifyBlockRejectsProposerOutsideSet covers a block that declares the honest set but
// was proposed by a stranger, so the proposer's COMMIT signature cannot be checked
// against a trusted key.
func TestVerifyBlockRejectsProposerOutsideSet(t *testing.T) {
	honest := newValidators(t, 4, 1, 10)
	attacker := newValidators(t, 1, 91, 90)[0]

	anchor := anchorAt(infos(honest), 0, make([]byte, 32))

	// The block declares the honest set and carries an honest PREPARE quorum, but the
	// stranger both proposed it and signed the COMMIT.
	block := buildBlock(t, blockSpec{
		index:      1,
		prevHash:   anchor.BlockHash,
		proposer:   0,
		signers:    []int{0, 1, 2},
		validators: infos(honest),
		proposerID: attacker.info.ValidatorID,
		proposerSK: attacker.sk,
	}, honest)

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("a block proposed by an untrusted identity verified")
	}
	if !errors.Is(err, ErrUnknownProposer) {
		t.Errorf("got %v, want ErrUnknownProposer", err)
	}
}

// TestVerifyBlockRejectsQuorumShortfall checks ceil(2N/3) is enforced against 4
// validators, where three are needed.
func TestVerifyBlockRejectsQuorumShortfall(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index:      1,
		prevHash:   anchor.BlockHash,
		proposer:   0,
		signers:    []int{0, 1}, // two of the three required
		validators: info,
	}, vs)

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("a block signed by 2 of 4 validators verified, where ceil(2N/3) = 3")
	}
	if !errors.Is(err, ErrQuorumNotMet) {
		t.Errorf("got %v, want ErrQuorumNotMet", err)
	}
}

// TestVerifyBlockRejectsDuplicateSignatures is the double-credit case: one key must not be
// able to sign twice and satisfy quorum on its own.
func TestVerifyBlockRejectsDuplicateSignatures(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index:      1,
		prevHash:   anchor.BlockHash,
		proposer:   0,
		signers:    []int{0},
		validators: info,
	}, vs)

	// Pad the payload with copies of validator 0's signature and mark bits 1 and 2, so
	// the bitmap claims three distinct signers and its population agrees with the payload
	// length. The quorum bit count and the bitmap check both pass, which leaves only
	// distinct-validator accounting able to catch this.
	//
	// Four validators means a one-byte bitmap, so validators 1 and 2 are bits 1 and 2 of
	// byte 0. Written out rather than computed, so the intent is visible.
	if len(block.PrepareSigsBitmap) != 1 {
		t.Fatalf("a four-validator block should have a one-byte bitmap, got %d bytes",
			len(block.PrepareSigsBitmap))
	}
	block.PrepareSigsBitmap[0] |= 1 << 1
	block.PrepareSigs = append(block.PrepareSigs, block.PrepareSigs[0])
	block.PrepareSigsBitmap[0] |= 1 << 2
	block.PrepareSigs = append(block.PrepareSigs, block.PrepareSigs[0])

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("three copies of one validator's signature satisfied quorum")
	}
	if !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrQuorumNotMet) {
		t.Errorf("got %v, want ErrBadSignature or ErrQuorumNotMet", err)
	}
}

// TestVerifyBlockRejectsBrokenChain covers a block that does not follow the anchor.
func TestVerifyBlockRejectsBrokenChain(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)

	t.Run("wrong prev hash", func(t *testing.T) {
		anchor := anchorAt(info, 0, []byte{0xAA, 0xBB})
		block := buildBlock(t, blockSpec{
			index: 1, prevHash: []byte{0xCC, 0xDD}, proposer: 0,
			signers: []int{0, 1, 2}, validators: info,
		}, vs)
		err := New(nil, nil).VerifyBlock(block, anchor)
		if !errors.Is(err, ErrChainBreak) {
			t.Errorf("got %v, want ErrChainBreak", err)
		}
	})

	t.Run("index skips ahead", func(t *testing.T) {
		anchor := anchorAt(info, 5, make([]byte, 32))
		block := buildBlock(t, blockSpec{
			index: 9, prevHash: anchor.BlockHash, proposer: 0,
			signers: []int{0, 1, 2}, validators: info,
		}, vs)
		err := New(nil, nil).VerifyBlock(block, anchor)
		if !errors.Is(err, ErrChainBreak) {
			t.Errorf("got %v, want ErrChainBreak: block 9 cannot be verified against an anchor at 5", err)
		}
	})
}

// TestVerifyBlockRejectsTamperedContents covers a block edited after signing. The
// signatures are over the block hash, so an edit that leaves the hash alone must be
// caught before the signatures are even examined.
func TestVerifyBlockRejectsTamperedContents(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0, 1, 2}, validators: info,
	}, vs)

	// Append an entry after the block was hashed and signed.
	block.Anchored = append(block.Anchored, chain.ProvenanceEntry{
		Hash: [32]byte{0xFF}, Submitter: [16]byte{1}, Timestamp: 1, Label: "injected",
	})

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("a block edited after signing verified")
	}
	if !errors.Is(err, ErrBlockHashMismatch) {
		t.Errorf("got %v, want ErrBlockHashMismatch", err)
	}
}

// TestVerifyBlockRejectsForgedSignatures covers a block whose bitmap claims a quorum it
// did not earn, padded with signatures from keys outside the trusted set.
func TestVerifyBlockRejectsForgedSignatures(t *testing.T) {
	honest := newValidators(t, 4, 1, 10)
	outsiders := newValidators(t, 4, 91, 90)
	info := infos(honest)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0, 1, 2}, validators: info,
	}, honest)

	// Replace two of the three signatures with ones from keys nobody trusts.
	block.PrepareSigs[1] = identity.SignDilithium(outsiders[1].sk, block.BlockHash)
	block.PrepareSigs[2] = identity.SignDilithium(outsiders[2].sk, block.BlockHash)

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("a block signed by untrusted keys verified")
	}
	if !errors.Is(err, ErrBadSignature) {
		t.Errorf("got %v, want ErrBadSignature", err)
	}
}

// TestVerifyBlockRejectsForgedCommitSignature covers a block whose proposer signature was
// forged while the PREPARE quorum is genuine.
func TestVerifyBlockRejectsForgedCommitSignature(t *testing.T) {
	honest := newValidators(t, 4, 1, 10)
	outsider := newValidators(t, 1, 91, 90)[0]
	info := infos(honest)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0, 1, 2}, validators: info,
	}, honest)
	block.CommitSig = identity.SignDilithium(outsider.sk, block.BlockHash)

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("a block with a forged COMMIT signature verified")
	}
	if !errors.Is(err, ErrBadSignature) {
		t.Errorf("got %v, want ErrBadSignature", err)
	}
}

// TestVerifyBlockRejectsBitmapPayloadMismatch covers a bitmap that claims more signers
// than the payload carries. The quorum check counts bits, so without this the block would
// pass quorum on signatures that were never supplied.
func TestVerifyBlockRejectsBitmapPayloadMismatch(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0}, validators: info,
	}, vs)
	// Mark validator 2 without adding a signature for it. Four validators means a one-byte
	// bitmap, so validator 2 is bit 2 of byte 0.
	if len(block.PrepareSigsBitmap) != 1 {
		t.Fatalf("a four-validator block should have a one-byte bitmap, got %d bytes",
			len(block.PrepareSigsBitmap))
	}
	block.PrepareSigsBitmap[0] |= 1 << 2

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("a bitmap claiming three signers with one signature verified")
	}
	if !errors.Is(err, ErrBitmapMismatch) {
		t.Errorf("got %v, want ErrBitmapMismatch", err)
	}
}

// TestVerifyBlockAcceptsDegradedQuorumForSmallSet covers §6.5's first clause: below four
// validators the chain is degraded, any single valid signature finalises a block, and the
// block must announce the mode.
//
// An earlier draft of this file asserted the opposite, on the reading that §6.5 only
// required the marker and did not lower the quorum. It says Q = 1 outright. A verifier that
// demanded ceil(2N/3) on a three-validator chain would reject every block the network
// accepts, which is the failure mode this test exists to catch.
func TestVerifyBlockAcceptsDegradedQuorumForSmallSet(t *testing.T) {
	vs := newValidators(t, 3, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0}, validators: info,
	}, vs)
	block.Metadata = map[string][]byte{DegradedLabel: []byte("true")}
	block.BlockHash = chain.ComputeBlockHash(block)
	block.PrepareSigs[0] = identity.SignDilithium(vs[0].sk, block.BlockHash)
	block.CommitSig = identity.SignDilithium(vs[0].sk, block.BlockHash)

	if err := New(nil, nil).VerifyBlock(block, anchor); err != nil {
		t.Fatalf("a properly announced degraded block was rejected: %v", err)
	}
}

// TestVerifyBlockRequiresDegradedMarkerForSmallSet covers §6.5's second clause: every
// block of a degraded chain must carry the marker. Without enforcing it, a sub-quorum
// chain could produce blocks indistinguishable from normal ones.
func TestVerifyBlockRequiresDegradedMarkerForSmallSet(t *testing.T) {
	vs := newValidators(t, 3, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0}, validators: info,
	}, vs)
	// No Metadata at all.

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("a degraded-mode block with no announcement verified")
	}
	if !errors.Is(err, ErrDegradedNotAnnounced) {
		t.Errorf("got %v, want ErrDegradedNotAnnounced", err)
	}
}

// TestVerifyBlockRejectsSelfDeclaredDegradedForNormalSet is the security property behind
// reading N from the trust anchor.
//
// A block in a chain of four or more must reach ceil(2N/3) = 3. If the verifier took the
// regime from the block's own metadata instead of the trusted set, a block could label
// itself degraded and satisfy quorum with a single signature.
func TestVerifyBlockRejectsSelfDeclaredDegradedForNormalSet(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0}, validators: info, // one signature, where three are required
	}, vs)
	block.Metadata = map[string][]byte{DegradedLabel: []byte("true")}
	block.BlockHash = chain.ComputeBlockHash(block)
	block.PrepareSigs[0] = identity.SignDilithium(vs[0].sk, block.BlockHash)
	block.CommitSig = identity.SignDilithium(vs[0].sk, block.BlockHash)

	err := New(nil, nil).VerifyBlock(block, anchor)
	if err == nil {
		t.Fatal("a block labelled degraded satisfied quorum in a chain of four")
	}
	if !errors.Is(err, ErrQuorumNotMet) {
		t.Errorf("got %v, want ErrQuorumNotMet", err)
	}
}

// TestVerifyBlockRequiresTrustAnchor checks verification fails closed without a trusted
// validator set rather than falling back to the block's own.
func TestVerifyBlockRequiresTrustAnchor(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))
	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0, 1, 2}, validators: info,
	}, vs)

	err := New(nil, nil).VerifyBlock(block, TrustAnchor{BlockIndex: 0, BlockHash: anchor.BlockHash})
	if err == nil {
		t.Fatal("verification succeeded with no trusted validator set")
	}
	if !errors.Is(err, ErrNoValidatorSet) {
		t.Errorf("got %v, want ErrNoValidatorSet", err)
	}
}

// TestVerifyBlockRejectsWrongProtocolVersion keeps v1 blocks out.
func TestVerifyBlockRejectsWrongProtocolVersion(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))
	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 0,
		signers: []int{0, 1, 2}, validators: info,
	}, vs)
	block.ProtocolVersion = 1

	err := New(nil, nil).VerifyBlock(block, anchor)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("got %v, want ErrUnsupportedVersion", err)
	}
}

// TestVerifyBlockFollowsRotation checks a block signed with a rotated key still verifies,
// which is what keeps a rotation from making a validator's history unverifiable to every
// observer.
func TestVerifyBlockFollowsRotation(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)
	anchor := anchorAt(info, 0, make([]byte, 32))

	// Validator 0 rotates to a fresh key effective in cycle 1, and signs with it.
	newPK, newSK, err := identity.GenerateDilithiumKeyFromSeed(rotationTestSeed(77))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rotation, err := chain.NewKeyRotationEntry(
		vs[0].info.ValidatorID, vs[0].sk, newPK, rotationTestVRF(), newSK,
		1, 1+10, time.Now().UnixNano(),
	)
	if err != nil {
		t.Fatalf("NewKeyRotationEntry: %v", err)
	}

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 1,
		signers: []int{0, 2, 3}, validators: info,
	}, vs)
	// Replace validator 0's signature and the proposer's, both signed with the new key.
	block.PrepareSigs[0] = identity.SignDilithium(newSK, block.BlockHash)
	block.CommitSig = identity.SignDilithium(vs[1].sk, block.BlockHash)

	anchor.Rotations = []*chain.KeyRotationEntry{rotation}
	if err := New(nil, nil).VerifyBlock(block, anchor); err != nil {
		t.Fatalf("a block signed with a rotated key was rejected: %v", err)
	}

	// Without the rotation in the trust anchor, the same block must not verify: the client
	// has no basis to accept the new key.
	plain := anchorAt(info, 0, make([]byte, 32))
	if err := New(nil, nil).VerifyBlock(block, plain); err == nil {
		t.Fatal("a block signed with a rotated key verified without the rotation being known")
	}
}

func rotationTestSeed(n byte) []byte {
	s := make([]byte, identity.Dilithium3SeedSize)
	for i := range s {
		s[i] = n + byte(i)
	}
	return s
}

func rotationTestVRF() [32]byte {
	var v [32]byte
	copy(v[:], []byte("rotation-test-vrf"))
	return v
}

// TestVerifyBlockAcceptsValidatorSetDuringRotation checks that comparing validator sets by
// identity rather than by key does not break during a rotation, which legitimately
// changes a validator's key.
func TestVerifyBlockAcceptsValidatorSetDuringRotation(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	anchor := anchorAt(infos(vs), 0, make([]byte, 32))

	newPK, _, err := identity.GenerateDilithiumKeyFromSeed(rotationTestSeed(88))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	declared := infos(vs)
	declared[0].Dilithium3PK = newPK // same identity, rotated key

	block := buildBlock(t, blockSpec{
		index: 1, prevHash: anchor.BlockHash, proposer: 1,
		signers: []int{0, 2, 3}, validators: declared,
	}, vs)

	// Signers 2 and 3 are honest; the quorum check will fail on validator 0's absent
	// rotation, but the set check must pass first.
	err = New(nil, nil).VerifyBlock(block, anchor)
	if errors.Is(err, ErrValidatorSetMismatch) {
		t.Fatal("a validator set with a rotated key was rejected as a different set")
	}
}

// TestReadOperations covers the §12.2 read side.
func TestReadOperations(t *testing.T) {
	vs := newValidators(t, 4, 1, 10)
	info := infos(vs)

	// BlockSource is indexed by block index, the way consensus.Engine is, so position 0
	// must be the genesis block.
	blocks := []*chain.Block{buildBlock(t, blockSpec{
		index: 0, prevHash: make([]byte, 32), proposer: 0,
		signers: []int{0, 1, 2}, validators: info,
	}, vs)}
	for i := 1; i <= 3; i++ {
		blocks = append(blocks, buildBlock(t, blockSpec{
			index: uint64(i), prevHash: blocks[i-1].BlockHash, proposer: 0,
			signers: []int{0, 1, 2}, validators: info,
		}, vs))
	}
	src := &source{blocks: blocks}
	svc := New(src, nil)

	t.Run("GetBlock", func(t *testing.T) {
		b, err := svc.GetBlock(2)
		if err != nil {
			t.Fatalf("GetBlock: %v", err)
		}
		if b.Index != 2 {
			t.Errorf("got index %d, want 2", b.Index)
		}
		if _, err := svc.GetBlock(99); !errors.Is(err, ErrBlockNotFound) {
			t.Errorf("got %v, want ErrBlockNotFound", err)
		}
	})

	t.Run("GetValidatorSet", func(t *testing.T) {
		set, err := svc.GetValidatorSet(info, 1)
		if err != nil {
			t.Fatalf("GetValidatorSet: %v", err)
		}
		if len(set) != 4 {
			t.Errorf("got %d validators, want 4", len(set))
		}
		if _, err := svc.GetValidatorSet(nil, 1); !errors.Is(err, ErrNoValidatorSet) {
			t.Errorf("got %v, want ErrNoValidatorSet", err)
		}
	})

	t.Run("StreamBlocks", func(t *testing.T) {
		ch, err := svc.StreamBlocks(context.Background(), 1)
		if err != nil {
			t.Fatalf("StreamBlocks: %v", err)
		}
		count := 0
		for range ch {
			count++
		}
		if count != 3 {
			t.Errorf("streamed %d blocks, want 3", count)
		}
	})

	t.Run("StreamBlocksIsBounded", func(t *testing.T) {
		// One request must not be able to walk an unbounded history.
		bounded := New(src, nil, WithMaxStreamBlocks(2))
		ch, err := bounded.StreamBlocks(context.Background(), 0)
		if err != nil {
			t.Fatalf("StreamBlocks: %v", err)
		}
		count := 0
		for range ch {
			count++
		}
		if count != 2 {
			t.Errorf("streamed %d blocks, want 2 under the cap", count)
		}
	})

	t.Run("StreamBlocksHonoursContext", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ch, err := svc.StreamBlocks(ctx, 1)
		if err != nil {
			t.Fatalf("StreamBlocks: %v", err)
		}
		count := 0
		for range ch {
			count++
		}
		if count != 0 {
			t.Errorf("a cancelled context still produced %d blocks", count)
		}
	})
}

// TestQuorumThreshold pins the arithmetic, including the degenerate cases.
func TestQuorumThreshold(t *testing.T) {
	cases := map[int]int{0: 0, 1: 1, 2: 2, 3: 2, 4: 3, 5: 4, 6: 4, 7: 5, 10: 7}
	for n, want := range cases {
		if got := normalQuorum(n); got != want {
			t.Errorf("quorum(%d) = %d, want %d", n, got, want)
		}
	}
}

// TestBitSetMatchesEngineLayout pins the bit order. If this disagreed with the engine, a
// light client would attribute every signature to the wrong validator -- and would either
// reject honest blocks or accept forged ones.
func TestBitSetMatchesEngineLayout(t *testing.T) {
	// Validator 0 -> bit 0 of byte 0; validator 7 -> bit 7 of byte 0; validator 8 ->
	// bit 0 of byte 1. Least significant bit first within each byte.
	bitmap := []byte{0x81, 0x01}
	cases := map[int]bool{
		0: true, 7: true, 1: false, 6: false,
		8: true, 15: false, 16: false,
	}
	for bit, want := range cases {
		if got := bitSet(bitmap, bit); got != want {
			t.Errorf("bitSet(%#x, %d) = %v, want %v", bitmap, bit, got, want)
		}
	}
	// Reads past the end are false rather than a panic, so a truncated bitmap cannot
	// credit a signer that was never named.
	if bitSet([]byte{0xFF}, 100) {
		t.Error("bitSet read past the end of the bitmap as set")
	}
}
