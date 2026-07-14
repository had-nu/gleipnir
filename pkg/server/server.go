// IPC gRPC server. Gleipnir reference implementation.
package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/validation"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

type Server struct {
	pb.UnimplementedProvenanceAnchorServer
	nodeID    string
	identity  *identity.UIDZeroSoulbound
	engine    *consensus.Engine
	keys      map[string]*identity.UIDZeroSoulbound
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

	s := &Server{
		nodeID:    nodeID,
		identity:  uid,
		engine:    eng,
		keys:      make(map[string]*identity.UIDZeroSoulbound),
		startTime: time.Now(),
	}
	s.keys[uid.ID()] = uid
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithKey(uid *identity.UIDZeroSoulbound) ServerOption {
	return func(s *Server) {
		s.keys[uid.ID()] = uid
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
			Accepted:  false,
			Status:    err.Error(),
			ErrorCode: code,
		}, nil
	}

	var h [32]byte
	copy(h[:], req.Hash)

	entry := chain.ProvenanceEntry{
		Hash:      h,
		Submitter: req.Submitter,
		Timestamp: req.Timestamp,
		Label:     req.Label,
	}
	if len(req.Approver) > 0 {
		entry.Approver = req.Approver
	}
	if len(req.Reference) > 0 {
		entry.Reference = req.Reference
	}
	if len(req.Signature) > 0 {
		entry.Signature = req.Signature
	}

	if err := s.engine.Enqueue(entry); err != nil {
		code, _ := validation.FromError(err)
		return &pb.SubmitResponse{
			Accepted:  false,
			Status:    err.Error(),
			ErrorCode: code,
		}, nil
	}

	return &pb.SubmitResponse{
		Accepted: true,
		Status:   "pending",
	}, nil
}

func (s *Server) authenticateSubmit(req *pb.SubmitRequest) error {
	submitterID := hex.EncodeToString(req.Submitter)
	uid, ok := s.keys[submitterID]
	if !ok {
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
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(req.Timestamp))
	signed := make([]byte, 0, len(req.Hash)+len(req.Submitter)+len(ts)+len(req.Label))
	signed = append(signed, req.Hash...)
	signed = append(signed, req.Submitter...)
	signed = append(signed, ts...)
	signed = append(signed, req.Label...)
	if !identity.VerifyDilithium(uid.PublicKey, signed, req.Signature) {
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
		Submitter:  proof.Submitter,
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
		Submitter:  proof.Submitter,
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

func (s *Server) GetBlock(ctx context.Context, req *pb.BlockRequest) (*pb.Block, error) {
	b := s.engine.GetBlock(req.Index)
	if b == nil {
		return &pb.Block{}, nil
	}

	pbEntries := make([]*pb.ProvenanceEntry, len(b.Anchored))
	for i, e := range b.Anchored {
		pbe := &pb.ProvenanceEntry{
			Hash:      e.Hash[:],
			Submitter: e.Submitter,
			Timestamp: e.Timestamp,
			Label:     e.Label,
		}
		if len(e.Approver) > 0 {
			pbe.Approver = e.Approver
		}
		if len(e.Reference) > 0 {
			pbe.Reference = e.Reference
		}
		if len(e.Signature) > 0 {
			pbe.Signature = e.Signature
		}
		pbEntries[i] = pbe
	}

	pbTriad := make([][]byte, 3)
	copy(pbTriad, b.Triad[:])

	pbSigs := make([][]byte, 3)
	copy(pbSigs, b.Sigs[:])

	return &pb.Block{
		Index:     b.Index,
		PrevHash:  b.PrevHash,
		StateRoot: b.StateRoot,
		Proposer:  b.Proposer,
		Triad:     pbTriad,
		Anchored:  pbEntries,
		Lambda1:   b.Lambda1,
		Timestamp: b.Timestamp,
		Sigs:      pbSigs,
	}, nil
}
