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
	"fmt"
	"time"

	pb "github.com/had-nu/gleipnir/pkg/server/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn   *grpc.ClientConn
	pb     pb.ProvenanceAnchorClient
	config Config
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
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
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

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Submit(ctx context.Context, hash []byte, label string) (*Ticket, error) {
	resp, err := c.pb.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash,
		Label:     label,
		Timestamp: time.Now().UnixNano(),
	})
	if err != nil {
		return nil, fmt.Errorf("submit: %w", err)
	}

	return &Ticket{
		Hash:      hash,
		Status:    resp.Status,
		BlockTime: resp.BlockTime,
	}, nil
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
