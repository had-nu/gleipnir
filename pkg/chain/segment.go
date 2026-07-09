package chain

import "context"

type Anchorer interface {
	Submit(ctx context.Context, hash [32]byte, submitter []byte, label string) (*Ticket, error)

	WaitForAnchor(ctx context.Context, hash [32]byte) (*AnchorProof, error)

	VerifyHash(ctx context.Context, hash [32]byte) (*AnchorProof, error)

	GetNetworkHealth(ctx context.Context) (*NetworkHealth, error)

	Close() error
}

type Ticket struct {
	Hash          [32]byte
	Status        string
	BlockIndex    uint64
	BlockTime     int64
}

type AnchorProof struct {
	Found         bool
	BlockIndex    uint64
	BlockTime     int64
	StateRoot     []byte
	SMTProof      []byte
	Submitter     []byte
	Label         string
}

type NetworkHealth struct {
	Lambda1       float64
	ActivePeers   int
	TotalPeers    int
	BlockHeight   uint64
	PendingHashes int
	AvgTPS        float64
}
