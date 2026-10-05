// Light client read operation tests — 3CP v2.0 §12.2.
//
//nolint:errcheck // test assertions
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/had-nu/gleipnir/pkg/chain"

	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

// anchorOne submits one entry and runs a cycle, returning the anchored entry's hash.
func anchorOne(t *testing.T, srv *Server, client pb.ProvenanceAnchorClient, label string) [32]byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	uid := srv.identity
	hash := sha256.Sum256([]byte(label))
	var submitter [16]byte
	copy(submitter[:], uid.RootID[:])
	ts := time.Now().UnixNano()
	sig := signSubmitRequest(uid, hash[:], submitter, ts, label)

	if _, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: hash[:], Submitter: submitter[:],
		Timestamp: ts, Label: label, Signature: sig,
	}); err != nil {
		t.Fatalf("SubmitHash: %v", err)
	}

	srv.Engine().RunCycle()
	return hash
}

// produceBlocks submits and anchors entries until the engine holds at least n blocks.
//
// RunCycle alone is not enough: the engine skips empty cycles, so a cycle with nothing
// queued produces no block and the fixture would never get off the ground.
func produceBlocks(t *testing.T, srv *Server, client pb.ProvenanceAnchorClient, n int) {
	t.Helper()
	for i := 0; i < n+2 && int(srv.Engine().BlockCount()) < n; i++ {
		anchorOne(t, srv, client, fmt.Sprintf("light-client-fixture-%d", i))
	}
	if int(srv.Engine().BlockCount()) < n {
		t.Fatalf("the engine produced %d blocks, want %d", srv.Engine().BlockCount(), n)
	}
}

// TestGetBlockReturnsStoredHash is the regression test for a defect that made the whole
// verification path impossible over gRPC.
//
// GetBlock used to fill block_hash by recomputing it from the block's contents. Every
// response was therefore self-consistent, and a client could not tell whether the block it
// was handed agreed with the hash that had been signed over -- which is exactly the check
// §12.2 asks of it. A corrupted or tampered block was laundered into a valid-looking one.
func TestGetBlockReturnsStoredHash(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	produceBlocks(t, srv, client, 1)

	resp, err := client.GetBlock(ctx, &pb.BlockRequest{Index: 0})
	if err != nil {
		t.Fatalf("GetBlock: %v", err)
	}
	if len(resp.BlockHash) != 32 {
		t.Fatalf("block_hash is %d bytes, want 32", len(resp.BlockHash))
	}

	// Corrupt the engine's own block, leaving its stored hash alone. The response must carry
	// the stale stored hash so the discrepancy is visible.
	block := srv.Engine().GetBlock(0)
	if block == nil {
		t.Fatal("no block at index 0")
	}
	stored := append([]byte(nil), block.BlockHash...)
	block.StateRoot[0] ^= 0xFF

	resp, err = client.GetBlock(ctx, &pb.BlockRequest{Index: 0})
	if err != nil {
		t.Fatalf("GetBlock: %v", err)
	}
	if !bytes.Equal(resp.BlockHash, stored) {
		t.Fatal("GetBlock recomputed the block hash instead of returning the stored one; " +
			"a client cannot detect a block whose contents were altered")
	}
	if bytes.Equal(resp.StateRoot, block.StateRoot[:0]) {
		t.Fatal("unexpected state root")
	}
}

// TestGetBlockCarriesEverythingAVerifierNeeds checks the message actually carries the fields
// §12.2 asks a client to verify. The previous message had only the v1-era fields, so a
// client could not check a PREPARE quorum, a COMMIT signature, or the validator set at all.
func TestGetBlockCarriesEverythingAVerifierNeeds(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	produceBlocks(t, srv, client, 1)

	resp, err := client.GetBlock(ctx, &pb.BlockRequest{Index: 0})
	if err != nil {
		t.Fatalf("GetBlock: %v", err)
	}

	if resp.ProtocolVersion != 2 {
		t.Errorf("protocol_version is %d, want 2", resp.ProtocolVersion)
	}
	if len(resp.Validators) == 0 {
		t.Error("the block carries no validator set, so a client cannot check any signature")
	}
	for i, v := range resp.Validators {
		if len(v.ValidatorId) != 16 {
			t.Errorf("validator %d: id is %d bytes, want 16", i, len(v.ValidatorId))
		}
		if len(v.Dilithium3Pk) != 1952 {
			t.Errorf("validator %d: Dilithium3Pk is %d bytes, want 1952", i, len(v.Dilithium3Pk))
		}
		// §7.2 MUSTs that VRFProof verification uses the peer's VRFPK, so a block that
		// omitted it would leave a verifier with nowhere to get it.
		if len(v.VrfPk) != 32 {
			t.Errorf("validator %d: VrfPk is %d bytes, want 32", i, len(v.VrfPk))
		}
	}
	if resp.Quorum == nil {
		t.Error("the block carries no quorum config")
	}
	if len(resp.PrepareSigsBitmap) == 0 {
		t.Error("the block carries no PREPARE bitmap")
	}
	if len(resp.CommitSig) == 0 {
		t.Error("the block carries no COMMIT signature")
	}

	// The bitmap and the payload must describe the same signers.
	bits := 0
	for _, b := range resp.PrepareSigsBitmap {
		for i := 0; i < 8; i++ {
			if b&(1<<i) != 0 {
				bits++
			}
		}
	}
	if bits != len(resp.PrepareSigs) {
		t.Errorf("bitmap marks %d signers but prepare_sigs holds %d; §5.3 compacts the "+
			"payload to the signers", bits, len(resp.PrepareSigs))
	}
}

// TestGetValidatorSetReturnsFullInfo checks the trust anchor a client receives is usable.
func TestGetValidatorSetReturnsFullInfo(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	resp, err := client.GetValidatorSet(ctx, &pb.ValidatorSetRequest{})
	if err != nil {
		t.Fatalf("GetValidatorSet: %v", err)
	}
	if len(resp.Validators) == 0 {
		t.Fatal("no validators returned")
	}
	for i, v := range resp.Validators {
		if len(v.ValidatorId) != 16 {
			t.Errorf("validator %d: id is %d bytes, want 16", i, len(v.ValidatorId))
		}
		if len(v.Dilithium3Pk) != 1952 {
			t.Errorf("validator %d: key is %d bytes, want 1952", i, len(v.Dilithium3Pk))
		}
		if len(v.VrfPk) != 32 {
			t.Errorf("validator %d: VRF key is %d bytes, want 32", i, len(v.VrfPk))
		}
	}
}

// TestGetValidatorSetMatchesBlockDeclaration checks the two agree. A light client verifies a
// block against this set, so if the served set and the block's own declaration diverged,
// every signature check would fail or, worse, some would pass against the wrong key.
func TestGetValidatorSetMatchesBlockDeclaration(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	produceBlocks(t, srv, client, 1)

	block, err := client.GetBlock(ctx, &pb.BlockRequest{Index: 0})
	if err != nil {
		t.Fatalf("GetBlock: %v", err)
	}
	set, err := client.GetValidatorSet(ctx, &pb.ValidatorSetRequest{})
	if err != nil {
		t.Fatalf("GetValidatorSet: %v", err)
	}
	if len(set.Validators) != len(block.Validators) {
		t.Fatalf("block declares %d validators, the node serves %d",
			len(block.Validators), len(set.Validators))
	}
	for i := range block.Validators {
		if !bytes.Equal(block.Validators[i].ValidatorId, set.Validators[i].ValidatorId) {
			t.Errorf("validator %d: block says %x, node serves %x",
				i, block.Validators[i].ValidatorId, set.Validators[i].ValidatorId)
		}
	}
}

// TestGetMerkleProofReturnsUsableProof checks the proof verifies against the returned root.
func TestGetMerkleProofReturnsUsableProof(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	// The proof has to be for a key that is in the tree, so anchor something first.
	key := anchorOne(t, srv, client, "merkle-proof-fixture")
	srv.Engine().RunCycle()

	resp, err := srv.GetMerkleProof(ctx, &pb.MerkleProofRequest{Key: key[:]})
	if err != nil {
		t.Fatalf("GetMerkleProof: %v", err)
	}
	if len(resp.Root) != 32 {
		t.Fatalf("root is %d bytes, want 32", len(resp.Root))
	}
	// Gleipnir's Sparse Merkle Tree emits a variable-length proof: Prove walks down until it
	// reaches a leaf and returns only the internal siblings it passed. A sparse tree holding
	// a single leaf therefore has an empty proof, and the root is that leaf's hash. Note this
	// differs from the pseudocode in SPEC §12.4, which indexes proof[depth] for a fixed 256
	// iterations; see the note in the PR description.
	if len(resp.Proof) > 255 {
		t.Fatalf("proof has %d siblings, more than the tree depth", len(resp.Proof))
	}

	// The proof must actually verify against the root that came with it, otherwise it is
	// decoration. This is the assertion that matters.
	proof := make([][32]byte, len(resp.Proof))
	for i, p := range resp.Proof {
		copy(proof[i][:], p)
	}
	var root [32]byte
	copy(root[:], resp.Root)
	if !srv.Engine().VerifySMT(key[:], key[:], root, proof) {
		t.Fatal("the proof did not verify against the root returned with it")
	}
}

// TestGetMerkleProofRejectsBadKey checks the key length is validated.
func TestGetMerkleProofRejectsBadKey(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	_, err := srv.GetMerkleProof(context.Background(), &pb.MerkleProofRequest{Key: []byte{1, 2, 3}})
	if err == nil {
		t.Fatal("a 3-byte key was accepted")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("got code %v, want InvalidArgument", code)
	}
}

// TestGetMerkleProofRejectsUnknownBlock checks a named block that does not exist is a
// NotFound rather than a proof against the wrong root.
func TestGetMerkleProofRejectsUnknownBlock(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	_, err := srv.GetMerkleProof(context.Background(), &pb.MerkleProofRequest{
		Key: make([]byte, 32), BlockIndex: 999,
	})
	if err == nil {
		t.Fatal("a proof was returned for a block that does not exist")
	}
	if code := status.Code(err); code != codes.NotFound {
		t.Errorf("got code %v, want NotFound", code)
	}
}

// TestStreamBlocksCarriesVerifiableFields checks the stream path serialises the same
// complete block as GetBlock. It goes through a different response path, so a field
// omitted there would leave a streaming client unable to verify anything it received.
func TestStreamBlocksCarriesVerifiableFields(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	produceBlocks(t, srv, client, 2)

	stream, err := client.StreamBlocks(ctx, &pb.BlockRange{From: 0, To: 1})
	if err != nil {
		t.Fatalf("StreamBlocks: %v", err)
	}

	seen := 0
	for {
		block, err := stream.Recv()
		if err != nil {
			break
		}
		seen++
		if block.ProtocolVersion != 2 {
			t.Errorf("block %d: protocol_version is %d, want 2", block.Index, block.ProtocolVersion)
		}
		if len(block.BlockHash) != 32 {
			t.Errorf("block %d: block_hash is %d bytes, want 32", block.Index, len(block.BlockHash))
		}
		if len(block.CommitSig) == 0 {
			t.Errorf("block %d: no COMMIT signature", block.Index)
		}
		if len(block.Validators) == 0 {
			t.Errorf("block %d: no validator set", block.Index)
		}
	}
	if seen == 0 {
		t.Fatal("the stream returned no blocks")
	}
}

// TestBlockProtoRoundTripsMetadata checks the degraded marker survives the wire, since §6.5
// makes it a MUST for every block of a degraded chain and a client enforces it.
func TestBlockProtoRoundTripsMetadata(t *testing.T) {
	original := &chain.Block{
		Index:           7,
		PrevHash:        make([]byte, 32),
		StateRoot:       make([]byte, 32),
		ProtocolVersion: 2,
		Quorum:          chain.QuorumConfig{TotalValidators: 3, RequiredSigs: 1},
		Metadata:        map[string][]byte{"3cp:degraded-block": []byte("true")},
	}

	converted := blockToProto(original)
	if string(converted.Metadata["3cp:degraded-block"]) != "true" {
		t.Fatalf("the degraded marker did not survive conversion: %v", converted.Metadata)
	}

	// The conversion must copy, not alias: a client mutating the proto must not reach into
	// the engine's block.
	converted.Metadata["3cp:degraded-block"] = []byte("false")
	if string(original.Metadata["3cp:degraded-block"]) != "true" {
		t.Error("mutating the converted metadata changed the engine's block")
	}
}
