// Storage interface for engine persistence (defined here to avoid import cycles).
package consensus

import (
	"context"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/state"
)

// EngineStorage defines the persistence operations for the consensus engine.
type EngineStorage interface {
	// Core state
	SaveState(ctx context.Context, st state.NetworkState) error
	LoadState(ctx context.Context) (state.NetworkState, bool, error)

	// Blocks
	SaveBlock(ctx context.Context, block chain.Block) error
	LoadBlocks(ctx context.Context) ([]chain.Block, error)
	GetBlock(ctx context.Context, index uint64) (*chain.Block, error)

	// Pending entries
	SavePending(ctx context.Context, entries []chain.ProvenanceEntry) error
	LoadPending(ctx context.Context) ([]chain.ProvenanceEntry, error)

	// Anchored proofs
	SaveAnchored(ctx context.Context, hash [32]byte, proof *chain.AnchorProof) error
	LoadAnchored(ctx context.Context) (map[[32]byte]*chain.AnchorProof, error)

	// SMT
	SaveSMT(ctx context.Context, tree interface{}) error
	LoadSMT(ctx context.Context) (interface{}, error)

	// Sub-chains
	SaveSubChain(ctx context.Context, id chain.SubChainID, sc interface{}) error
	LoadSubChains(ctx context.Context) (map[chain.SubChainID]interface{}, error)

	// Metadata
	SaveMeta(ctx context.Context, key string, value []byte) error
	LoadMeta(ctx context.Context, key string) ([]byte, error)

	Close() error
}