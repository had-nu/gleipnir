// Package client provides a Go client for the Immutable Provenance Chain (IPC) protocol.
// Gleipnir is the reference implementation.
//
// Usage:
//
//	c, err := client.New("localhost:50051")
//	defer c.Close()
//
//	ticket, err := c.Submit(ctx, hash, submitter, "my-label")
//	proof, err := c.WaitForAnchor(ctx, hash[:])
package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/had-nu/gleipnir/pkg/identity"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn     *grpc.ClientConn
	pb       pb.ProvenanceAnchorClient
	config   Config
	identity *identity.UIDZeroSoulbound
}

type Config struct {
	Addr        string
	DialTimeout time.Duration
}

func DefaultConfig(addr string) Config {
	return Config{
		Addr:        addr,
		DialTimeout: 10 * time.Second,
	}
}

func New(addr string) (*Client, error) {
	return NewWithConfig(DefaultConfig(addr))
}

func NewWithConfig(cfg Config) (*Client, error) {
	conn, err := grpc.NewClient(cfg.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.Addr, err)
	}

	return &Client{
		conn:   conn,
		pb:     pb.NewProvenanceAnchorClient(conn),
		config: cfg,
	}, nil
}

func NewWithIdentity(addr string, uid *identity.UIDZeroSoulbound) (*Client, error) {
	c, err := New(addr)
	if err != nil {
		return nil, err
	}
	c.identity = uid
	return c, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Submit(ctx context.Context, hash []byte, label string) (*Ticket, error) {
	req := &pb.SubmitRequest{
		Hash:      hash,
		Label:     label,
		Timestamp: time.Now().UnixNano(),
	}
	if c.identity != nil {
		req.Submitter = c.identity.RootID
		req.Signature = signPayload(c.identity, req.Hash, req.Submitter, req.Timestamp, req.Label)
	}
	resp, err := c.pb.SubmitHash(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("submit: %w", err)
	}

	return &Ticket{
		Hash:      hash,
		Status:    resp.Status,
		BlockTime: resp.BlockTime,
		ErrorCode: resp.ErrorCode,
	}, nil
}

func (c *Client) SubmitSigned(ctx context.Context, hash []byte, submitter []byte, label string, approver []byte, reference []byte, signer *identity.UIDZeroSoulbound) (*Ticket, error) {
	ts := time.Now().UnixNano()
	req := &pb.SubmitRequest{
		Hash:      hash,
		Submitter: submitter,
		Label:     label,
		Timestamp: ts,
		Signature: signPayload(signer, hash, submitter, ts, label),
	}
	if len(approver) > 0 {
		req.Approver = approver
	}
	if len(reference) > 0 {
		req.Reference = reference
	}
	resp, err := c.pb.SubmitHash(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("submit: %w", err)
	}

	return &Ticket{
		Hash:      hash,
		Status:    resp.Status,
		BlockTime: resp.BlockTime,
		ErrorCode: resp.ErrorCode,
	}, nil
}

func signPayload(uid *identity.UIDZeroSoulbound, hash, submitter []byte, ts int64, label string) []byte {
	tsLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsLE, uint64(ts))
	signed := make([]byte, 0, len(hash)+len(submitter)+len(tsLE)+len(label))
	signed = append(signed, hash...)
	signed = append(signed, submitter...)
	signed = append(signed, tsLE...)
	signed = append(signed, label...)
	return identity.SignDilithium(uid.SecretKey, signed)
}

func (c *Client) WaitForAnchor(ctx context.Context, hash []byte) (*AnchorProof, error) {
	resp, err := c.pb.WaitForAnchor(ctx, &pb.WaitRequest{Hash: hash})
	if err != nil {
		return nil, fmt.Errorf("wait: %w", err)
	}
	return anchorProofFromPB(resp), nil
}

func (c *Client) Verify(ctx context.Context, hash []byte) (*AnchorProof, error) {
	resp, err := c.pb.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash})
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	return anchorProofFromPB(resp), nil
}

func (c *Client) Health(ctx context.Context) (*Health, error) {
	resp, err := c.pb.GetHealth(ctx, &pb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("health: %w", err)
	}
	return &Health{
		NodeID:    resp.NodeId,
		Status:    resp.Status,
		Height:    resp.BlockHeight,
		Lambda1:   resp.Lambda1,
		Peers:     int(resp.ActivePeers),
		Pending:   int(resp.PendingHashes),
	}, nil
}

func (c *Client) StateRoot(ctx context.Context) (*StateRoot, error) {
	resp, err := c.pb.GetCurrentStateRoot(ctx, &pb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("state root: %w", err)
	}
	return &StateRoot{
		Root:  resp.StateRoot,
		Block: resp.BlockIndex,
	}, nil
}

type Ticket struct {
	Hash      []byte
	Status    string
	BlockTime int64
	ErrorCode string
}

type AnchorProof struct {
	Found      bool
	BlockIndex uint64
	BlockTime  int64
	StateRoot  []byte
	Submitter  []byte
	Label      string
}

type Health struct {
	NodeID  string
	Status  string
	Height  uint64
	Lambda1 float32
	Peers   int
	Pending int
}

type StateRoot struct {
	Root  []byte
	Block uint64
}

func anchorProofFromPB(pb *pb.AnchorProof) *AnchorProof {
	if pb == nil {
		return nil
	}
	return &AnchorProof{
		Found:      pb.Found,
		BlockIndex: pb.BlockIndex,
		BlockTime:  pb.BlockTime,
		StateRoot:  pb.StateRoot,
		Submitter:  pb.Submitter,
		Label:      pb.Label,
	}
}
