// IPC gRPC server. Gleipnir reference implementation.
package server

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
	"github.com/had-nu/gleipnir/pkg/validation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	pb.UnimplementedProvenanceAnchorServer
	nodeID    string
	identity  *identity.UIDZeroSoulbound
	engine    *consensus.Engine
	registry  *identity.Registry
	startTime time.Time
}

type ServerOption func(*Server)

func NewServer(nodeID string, uid *identity.UIDZeroSoulbound, opts ...ServerOption) *Server {
	node := consensus.Node{
		UID:  *uid,
		Addr: nodeID,
	}
	eng := consensus.NewEngine(node, 3*time.Second)
	eng.Start()

	// Initialize identity registry with the node's identity
	registry := identity.NewRegistry()
	_ = registry.Register(uid.ID(), uid.PublicKey[:])

	s := &Server{
		nodeID:    nodeID,
		identity:  uid,
		engine:    eng,
		registry:  registry,
		startTime: time.Now(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithKey(uid *identity.UIDZeroSoulbound) ServerOption {
	return func(s *Server) {
		_ = s.registry.Register(uid.ID(), uid.PublicKey[:])
	}
}

func (s *Server) Engine() *consensus.Engine {
	return s.engine
}

func (s *Server) Stop() {
	s.engine.Stop()
}

func (s *Server) SubmitHash(ctx context.Context, req *pb.SubmitRequest) (*pb.SubmitResponse, error) {
	if err := s.authenticateSubmit(req); err != nil {
		code, _ := validation.FromError(err)
		return &pb.SubmitResponse{
			TxId:      req.Hash[:],
			Accepted:  false,
			Status:    err.Error(),
			ErrorCode: code,
		}, nil
	}

	var h [32]byte
	copy(h[:], req.Hash)

	var submitter [16]byte
	copy(submitter[:], req.Submitter)

	var approver *[16]byte
	if len(req.Approver) > 0 {
		var a [16]byte
		copy(a[:], req.Approver)
		approver = &a
	}

	var reference *[32]byte
	if len(req.Reference) > 0 {
		var r [32]byte
		copy(r[:], req.Reference)
		reference = &r
	}

	entry := chain.ProvenanceEntry{
		Hash:      h,
		Submitter: submitter,
		Timestamp: req.Timestamp,
		Label:     req.Label,
		Approver:  approver,
		Reference: reference,
		Signature: req.Signature,
	}

	if err := s.engine.Enqueue(entry); err != nil {
		code, _ := validation.FromError(err)
		return &pb.SubmitResponse{
			TxId:      req.Hash[:],
			Accepted:  false,
			Status:    err.Error(),
			ErrorCode: code,
		}, nil
	}

	return &pb.SubmitResponse{
		TxId:       req.Hash[:],
		Accepted:  true,
		Status:    "pending",
		BlockIndex: 0,
		BlockTime:  0,
	}, nil
}

func (s *Server) authenticateSubmit(req *pb.SubmitRequest) error {
	// 1. Lookup submitter's public key from registry
	pubKey, err := s.registry.Lookup(hex.EncodeToString(req.Submitter))
	if err != nil {
		return validation.WrapValidationError(
			validation.ErrCodeSubmitterMismatch,
			"unknown submitter",
			validation.ErrUnknownSubmitter,
		)
	}

	if len(req.Signature) == 0 {
		return validation.WrapValidationError(
			validation.ErrCodeInvalidSignature,
			"missing signature",
			validation.ErrInvalidSignature,
		)
	}

	// Verify Dilithium3 signature
	if !identity.VerifySignature(pubKey, req.Hash, req.Submitter, req.Timestamp, req.Label, req.Signature) {
		return validation.WrapValidationError(
			validation.ErrCodeInvalidSignature,
			"signature does not match submitter",
			validation.ErrInvalidSignature,
		)
	}
	return nil
}

func (s *Server) WaitForAnchor(ctx context.Context, req *pb.WaitRequest) (*pb.AnchorProof, error) {
	var h [32]byte
	copy(h[:], req.Hash)

	proof, err := s.engine.WaitForAnchor(ctx, h)
	if err != nil {
		return nil, err
	}

	return &pb.AnchorProof{
		Found:      proof.Found,
		BlockIndex: proof.BlockIndex,
		BlockTime:  proof.BlockTime,
		StateRoot:  proof.StateRoot,
		SmtProof:   proof.SMTProof,
		Submitter:  proof.Submitter[:],
		Label:      proof.Label,
	}, nil
}

func (s *Server) VerifyHash(ctx context.Context, req *pb.VerifyRequest) (*pb.AnchorProof, error) {
	var h [32]byte
	copy(h[:], req.Hash)

	proof, ok := s.engine.LookupHash(h)
	if !ok {
		return &pb.AnchorProof{Found: false}, nil
	}

	return &pb.AnchorProof{
		Found:      true,
		BlockIndex: proof.BlockIndex,
		BlockTime:  proof.BlockTime,
		StateRoot:  proof.StateRoot,
		SmtProof:   proof.SMTProof,
		Submitter:  proof.Submitter[:],
		Label:      proof.Label,
	}, nil
}

func (s *Server) GetCurrentStateRoot(ctx context.Context, req *pb.Empty) (*pb.StateRootResponse, error) {
	root := s.engine.GetStateRoot()
	health := s.engine.GetHealth()

	return &pb.StateRootResponse{
		StateRoot:  root,
		BlockIndex: s.engine.BlockCount(),
		Lambda1:    float32(health.Lambda1),
	}, nil
}

func (s *Server) GetHealth(ctx context.Context, req *pb.Empty) (*pb.HealthResponse, error) {
	health := s.engine.GetHealth()
	root := s.engine.GetStateRoot()

	return &pb.HealthResponse{
		NodeId:       s.nodeID,
		Status:       "running",
		BlockHeight:  health.BlockHeight,
		CurrentRoot:  root,
		Lambda1:      float32(health.Lambda1),
		ActivePeers:  uint32(health.ActivePeers),
		TotalPeers:   uint32(health.TotalPeers),
		PendingHashes: uint64(health.PendingHashes),
		AvgTps:       0,
	}, nil
}

// SubmitKeyRotation rotates this node's validator signing key (SPEC §8).
//
// The client supplies the incoming public keys and the incoming key's signature over
// the canonical rotation payload; the node contributes its outgoing signature. The
// incoming secret key never reaches this process, so a validator can rotate to a key
// held in an HSM or KMS.
//
// A rotation that violates any of the five rules of SPEC §8.2 is reported as
// "rejected" with the reason, rather than as a transport error: a rejected rotation is
// an expected outcome of client input, not a server fault.
func (s *Server) SubmitKeyRotation(ctx context.Context, req *pb.KeyRotationRequest) (*pb.KeyRotationResponse, error) {
	if len(req.NewDilithiumPublicKey) != chain.KeyRotationPublicKeySize {
		return nil, status.Errorf(codes.InvalidArgument,
			"new Dilithium3 public key must be %d bytes, got %d",
			chain.KeyRotationPublicKeySize, len(req.NewDilithiumPublicKey))
	}
	if len(req.NewVrfPublicKey) != chain.KeyRotationVRFKeySize {
		return nil, status.Errorf(codes.InvalidArgument,
			"new VRF public key must be %d bytes, got %d",
			chain.KeyRotationVRFKeySize, len(req.NewVrfPublicKey))
	}
	// Rule 2 of SPEC §8.2 requires the incoming key to sign. Without a client-supplied
	// signature there is nothing to satisfy it with, and the entry would be rejected
	// later with a far less obvious error.
	if len(req.SignatureNew) != chain.KeyRotationSignatureSize {
		return nil, status.Errorf(codes.InvalidArgument,
			"signature_new must be %d bytes, got %d",
			chain.KeyRotationSignatureSize, len(req.SignatureNew))
	}

	var newPK [chain.KeyRotationPublicKeySize]byte
	copy(newPK[:], req.NewDilithiumPublicKey)
	var newVRF [chain.KeyRotationVRFKeySize]byte
	copy(newVRF[:], req.NewVrfPublicKey)

	entry, err := s.engine.RotateKey(ctx, newPK, newVRF, req.SignatureNew,
		req.EffectiveCycle, req.ExpiryCycle)
	if err != nil {
		resp := &pb.KeyRotationResponse{
			Status:         "rejected",
			Error:          err.Error(),
			EffectiveCycle: req.EffectiveCycle,
			ExpiryCycle:    req.ExpiryCycle,
		}
		if entry != nil {
			resp.EntryHash = entry.Hash[:]
		}
		if code, ok := validation.FromError(err); ok {
			resp.ErrorCode = code
		}
		return resp, nil
	}

	return &pb.KeyRotationResponse{
		EntryHash:      entry.Hash[:],
		Status:         "pending",
		EffectiveCycle: entry.EffectiveCycle,
		ExpiryCycle:    entry.ExpiryCycle,
	}, nil
}

// GetActivePublicKey reports the validator keys authoritative in a cycle. Two keys are
// returned during a rotation's overlap window (SPEC §8).
func (s *Server) GetActivePublicKey(ctx context.Context, req *pb.ActiveKeyRequest) (*pb.ActiveKeyResponse, error) {
	validatorID := s.engine.NodeUID().RootID
	if len(req.ValidatorId) > 0 {
		if len(req.ValidatorId) != 16 {
			return nil, status.Errorf(codes.InvalidArgument,
				"validator_id must be 16 bytes, got %d", len(req.ValidatorId))
		}
		copy(validatorID[:], req.ValidatorId)
	}

	cycle := req.Cycle
	if req.Cycle == 0 {
		cycle = s.engine.Cycle()
	}

	keys, err := s.engine.KeyRotationValidator().GetActivePublicKey(validatorID, cycle)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "no active key for validator: %v", err)
	}

	out := make([][]byte, 0, len(keys))
	for _, k := range keys {
		out = append(out, k[:])
	}
	return &pb.ActiveKeyResponse{PublicKeys: out, InOverlap: len(keys) > 1}, nil
}

func (s *Server) GetBlock(ctx context.Context, req *pb.BlockRequest) (*pb.Block, error) {
	b := s.engine.GetBlock(req.Index)
	if b == nil {
		return &pb.Block{}, nil
	}
	return blockToProto(b), nil
}

// blockToProto converts a block for the wire.
//
// BlockHash is the value the block stores, not one recomputed from its contents. Serving
// a recomputed hash would make every response self-consistent, and a client could then
// never tell whether the block it was handed agrees with the hash that was signed over --
// which is the check the whole verification path rests on. If a block's stored hash is
// wrong, the client has to be the one to find out.
func blockToProto(b *chain.Block) *pb.Block {
	pbEntries := make([]*pb.ProvenanceEntry, len(b.Anchored))
	for i := range b.Anchored {
		e := &b.Anchored[i]
		var approver, reference []byte
		if e.Approver != nil {
			approver = e.Approver[:]
		}
		if e.Reference != nil {
			reference = e.Reference[:]
		}
		pbEntries[i] = &pb.ProvenanceEntry{
			Hash:       e.Hash[:],
			Submitter:  e.Submitter[:],
			Timestamp:  e.Timestamp,
			Label:      e.Label,
			Approver:   approver,
			Reference:  reference,
			Signature:  e.Signature,
			MandateRef: mandateRefBytes(e.MandateRef),
		}
	}

	pbValidators := make([]*pb.ValidatorInfo, len(b.Validators))
	for i := range b.Validators {
		v := &b.Validators[i]
		pbValidators[i] = &pb.ValidatorInfo{
			ValidatorId:  v.ValidatorID[:],
			Dilithium3Pk: v.Dilithium3PK[:],
			VrfPk:        v.VRFPK[:],
			ContractHash: v.ContractHash[:],
		}
	}

	pbSigs := make([][]byte, len(b.PrepareSigs))
	for i, sig := range b.PrepareSigs {
		pbSigs[i] = append([]byte(nil), sig...)
	}

	pbAnchors := make([]string, len(b.ExternalAnchors))
	copy(pbAnchors, b.ExternalAnchors)

	var metadata map[string][]byte
	if len(b.Metadata) > 0 {
		metadata = make(map[string][]byte, len(b.Metadata))
		for k, v := range b.Metadata {
			metadata[k] = append([]byte(nil), v...)
		}
	}

	return &pb.Block{
		Index:      b.Index,
		PrevHash:   b.PrevHash,
		StateRoot:  b.StateRoot,
		Proposer:   b.Proposer[:],
		Anchored:   pbEntries,
		Lambda1:    b.Lambda1,
		Timestamp:  b.Timestamp,
		Validators: pbValidators,
		Quorum: &pb.QuorumConfig{
			TotalValidators: nonNegativeUint64(b.Quorum.TotalValidators),
			RequiredSigs:    nonNegativeUint64(b.Quorum.RequiredSigs),
		},
		BlockHash:         b.BlockHash,
		ProtocolVersion:   uint32(b.ProtocolVersion),
		PrepareSigsBitmap: b.PrepareSigsBitmap,
		PrepareSigs:       pbSigs,
		CommitSig:         b.CommitSig,
		ExternalAnchors:   pbAnchors,
		KeyRotationEpoch:  b.KeyRotationEpoch,
		LegacyAnchor:      b.LegacyAnchor,
		Metadata:          metadata,
	}
}

// mandateRefBytes renders an optional mandate reference as bytes, or nil when absent.
func mandateRefBytes(ref *[32]byte) []byte {
	if ref == nil {
		return nil
	}
	return ref[:]
}
