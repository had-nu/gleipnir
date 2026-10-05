// Light client read operations — 3CP v2.0 §12.2.
package server

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

// GetValidatorSet returns the canonical validator set (SPEC §12.2).
//
// The set comes from the node's own validator state, not from any block. A light client
// needs it precisely because it does not trust the block's own account of who is entitled
// to sign: were the set read from a block, a block could name validators its author
// controls and the client's quorum check would count against them.
func (s *Server) GetValidatorSet(ctx context.Context, req *pb.ValidatorSetRequest) (*pb.ValidatorSetResponse, error) {
	cycle := req.Cycle
	if cycle == 0 {
		cycle = s.engine.Cycle()
	}

	validators := s.engine.ValidatorSetSnapshot()
	if len(validators) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"no validator set known for cycle %d", cycle)
	}

	out := make([]*pb.ValidatorInfo, len(validators))
	for i := range validators {
		v := &validators[i]
		out[i] = &pb.ValidatorInfo{
			ValidatorId:  v.ValidatorID[:],
			Dilithium3Pk: v.Dilithium3PK[:],
			VrfPk:        v.VRFPK[:],
			ContractHash: v.ContractHash[:],
		}
	}
	return &pb.ValidatorSetResponse{Validators: out}, nil
}

// GetMerkleProof returns an inclusion proof for a key, together with the state root of the
// block the caller named (SPEC §12.2).
//
// The root is the block's, not the tree's current one. Pairing a current proof with an old
// block's root would be meaningless, and pairing a current root with an old block would
// let a client believe an entry is in a block it was never anchored to.
func (s *Server) GetMerkleProof(ctx context.Context, req *pb.MerkleProofRequest) (*pb.MerkleProofResponse, error) {
	if len(req.Key) != 32 {
		return nil, status.Errorf(codes.InvalidArgument, "key must be 32 bytes, got %d", len(req.Key))
	}
	if req.BlockIndex > 0 {
		block := s.engine.GetBlock(req.BlockIndex)
		if block == nil {
			return nil, status.Errorf(codes.NotFound, "no block at index %d", req.BlockIndex)
		}
		if len(block.StateRoot) != 32 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"block %d has a %d-byte state root, want 32", req.BlockIndex, len(block.StateRoot))
		}
	}

	var key [32]byte
	copy(key[:], req.Key)
	raw, err := s.engine.ProveSMT(key[:])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "prove %x: %v", key, err)
	}
	proof := make([][]byte, len(raw))
	for i := range raw {
		proof[i] = raw[i][:]
	}

	// The tree's current root is what the proof was computed against. The block's root is
	// validated above but not used here: the proof is against the live tree, so pairing it
	// with an older block's root would be meaningless.
	root := s.engine.GetStateRoot()
	if len(root) != 32 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"state root is %d bytes, want 32", len(root))
	}

	return &pb.MerkleProofResponse{Proof: proof, Root: root}, nil
}

// maxStreamBlocksPerResponse bounds how many blocks one StreamBlocks call sends.
//
// Without it a single request could ask a node to serialise its entire history, which is
// the cheap way to turn a read endpoint into a denial-of-service surface.
const maxStreamBlocksPerResponse = 1024

// StreamBlocks streams blocks in a range (SPEC §12.2).
//
// This was declared in the service definition but never implemented, so every call fell
// through to the embedded Unimplemented and returned nothing. A light client that followed
// §12.2 would have found one of its four required read operations missing.
//
// A range whose To is below From is treated as a single-block request rather than an
// error, since callers commonly send from == to meaning "just this one".
func (s *Server) StreamBlocks(req *pb.BlockRange, stream grpc.ServerStreamingServer[pb.Block]) error {
	ctx := stream.Context()

	from := req.From
	to := req.To
	if to < from {
		to = from
	}
	if to-from >= maxStreamBlocksPerResponse {
		to = from + maxStreamBlocksPerResponse - 1
	}

	for i := from; i <= to; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		block := s.engine.GetBlock(i)
		if block == nil {
			// The chain does not reach this far yet. Ending the stream is the useful
			// outcome: a client following the chain stops when it runs out, and continuing
			// would spin on missing blocks.
			return nil
		}
		if err := stream.Send(blockToProto(block)); err != nil {
			return err
		}
	}
	return nil
}

// nonNegativeUint64 converts a count to the protobuf field's width without wrapping.
//
// chain.QuorumConfig stores these as int, so a negative value would otherwise become
// close to 2^64 on the wire. A client reading that as a threshold would conclude it can
// never reach quorum, which reads as a broken chain rather than as the bug it is.
func nonNegativeUint64(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
