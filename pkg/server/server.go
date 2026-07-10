// IPC gRPC server. Gleipnir reference implementation.
package server

import (
	"context"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

type Server struct {
	pb.UnimplementedProvenanceAnchorServer
	nodeID    string
	identity  *identity.UIDZeroSoulbound
	engine    *consensus.Engine
	startTime time.Time
}

func NewServer(nodeID string, uid *identity.UIDZeroSoulbound) *Server {
	node := consensus.Node{
		UID:  *uid,
		Addr: nodeID,
	}
	eng := consensus.NewEngine(node, 3*time.Second)
	eng.Start()

	return &Server{
		nodeID:    nodeID,
		identity:  uid,
		engine:    eng,
		startTime: time.Now(),
	}
}

func (s *Server) Stop() {
	s.engine.Stop()
}

func (s *Server) SubmitHash(ctx context.Context, req *pb.SubmitRequest) (*pb.SubmitResponse, error) {
	var h [32]byte
	copy(h[:], req.Hash)

	entry := chain.ProvenanceEntry{
		Hash:      h,
		Submitter: req.Submitter,
		Timestamp: req.Timestamp,
		Label:     req.Label,
	}
	s.engine.Enqueue(entry)

	return &pb.SubmitResponse{
		Accepted: true,
		Status:   "pending",
	}, nil
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
		pbEntries[i] = &pb.ProvenanceEntry{
			Hash:      e.Hash[:],
			Submitter: e.Submitter,
			Timestamp: e.Timestamp,
			Label:     e.Label,
		}
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
