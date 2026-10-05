// Mandate compliance endpoints — 3CP v2.0 §15.
package server

import (
	"context"
	"math"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/validation"

	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

// SubmitMandate installs a mandate on this node.
//
// The node checks the mandate's authority signature against a registered key before it
// becomes enforceable, so a caller cannot install policy in another node's name. The
// check is not optional: an unauthenticated mandate would govern every entry that
// referenced it, on this node and, once gossiped, on others.
func (s *Server) SubmitMandate(ctx context.Context, req *pb.MandateRequest) (*pb.MandateResponse, error) {
	mandate, err := chain.UnmarshalMandateEntry(req.Mandate)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "malformed mandate: %v", err)
	}

	if err := s.engine.SubmitMandate(mandate); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "mandate rejected: %v", err)
	}
	return &pb.MandateResponse{MandateId: mandate.ID[:], Version: mandate.Version}, nil
}

// GetMandate returns a mandate body by identifier.
func (s *Server) GetMandate(ctx context.Context, req *pb.GetMandateRequest) (*pb.GetMandateResponse, error) {
	if len(req.MandateId) != 32 {
		return nil, status.Errorf(codes.InvalidArgument, "mandate_id must be 32 bytes, got %d", len(req.MandateId))
	}
	var id [32]byte
	copy(id[:], req.MandateId)

	mandate, ok := s.engine.MandateBody(id)
	if !ok {
		// Fall back to the resolver, which also knows mandates registered before this
		// node started tracking bodies.
		m, found := s.engine.MandateResolver().GetMandateByID(id)
		if !found {
			return nil, status.Errorf(codes.NotFound, "no mandate with id %x", id)
		}
		mandate = m
	}

	encoded, err := chain.MarshalMandateEntry(mandate)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode mandate: %v", err)
	}
	return &pb.GetMandateResponse{Mandate: encoded}, nil
}

// GetActiveMandates lists the mandates in force at a timestamp.
func (s *Server) GetActiveMandates(ctx context.Context, req *pb.GetActiveMandatesRequest) (*pb.GetActiveMandatesResponse, error) {
	mandates, err := s.engine.ActiveMandates(req.Timestamp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list active mandates: %v", err)
	}

	out := make([][]byte, 0, len(mandates))
	for _, m := range mandates {
		encoded, err := chain.MarshalMandateEntry(m)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encode mandate %x: %v", m.ID, err)
		}
		out = append(out, encoded)
	}
	return &pb.GetActiveMandatesResponse{Mandates: out}, nil
}

// CheckCompliance asks whether the chain has honoured a mandate over a window.
//
// The result is derived from this node's own blocks, so a node that has not seen the
// whole window will report gaps that a fully synchronised node would not. That is a
// property of the query, not an error: the report says what this node can attest to.
func (s *Server) CheckCompliance(ctx context.Context, req *pb.ComplianceCheckRequest) (*pb.ComplianceReport, error) {
	if len(req.MandateId) != 32 {
		return nil, status.Errorf(codes.InvalidArgument, "mandate_id must be 32 bytes, got %d", len(req.MandateId))
	}
	var id [32]byte
	copy(id[:], req.MandateId)

	window := validation.ComplianceWindow{
		StartTimestamp: req.StartTimestamp,
		EndTimestamp:   req.EndTimestamp,
		StartCycle:     req.StartCycle,
		EndCycle:       req.EndCycle,
	}
	if err := window.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid window: %v", err)
	}

	report, err := s.engine.CheckCompliance(id, window)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "compliance check failed: %v", err)
	}
	return complianceReportToProto(report), nil
}

// complianceReportToProto converts an internal report, mirroring
// compliance-verification in spec/schemas/mandate.cddl.
func complianceReportToProto(report *validation.ComplianceReport) *pb.ComplianceReport {
	gaps := make([]*pb.ComplianceGap, 0, len(report.Gaps))
	for i := range report.Gaps {
		g := &report.Gaps[i]
		gaps = append(gaps, &pb.ComplianceGap{
			MandateId:           g.MandateID[:],
			RuleIndex:           clampUint32(g.RuleIndex),
			EventClass:          g.EventClass,
			ExpectedWindowStart: g.WindowStart,
			ExpectedWindowEnd:   g.WindowEnd,
			Status:              g.Status,
			Details:             g.Details,
			MissingFields:       g.MissingFields,
		})
	}

	return &pb.ComplianceReport{
		MandateId:      report.MandateID[:],
		MandateLabel:   report.MandateLabel,
		StartTimestamp: report.Window.StartTimestamp,
		EndTimestamp:   report.Window.EndTimestamp,
		TotalExpected:  clampUint32(report.TotalExpected),
		TotalAnchored:  clampUint32(report.TotalAnchored),
		ComplianceRate: report.ComplianceRate,
		Gaps:           gaps,
		Timestamp:      report.Timestamp,
	}
}

// clampUint32 converts a count to the protobuf field's width without wrapping.
//
// A negative value would otherwise become a very large one, which is the worse failure
// in a report an auditor reads: "4 billion expected" reads as a broken mandate rather
// than as the bug it is. Saturating keeps the number on the side of too small, and both
// counts are bounded in practice by the mandate's own rule count.
func clampUint32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}
