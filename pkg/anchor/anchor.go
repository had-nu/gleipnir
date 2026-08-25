// IPC Anchor Publisher — publishes final blocks to public-readable storage.
// Implements 3CP spec §11.1 Anchor Publishers.
package anchor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"lukechampine.com/blake3"
)

var (
	ErrPublisherNotConfigured = errors.New("anchor publisher not configured")
	ErrUnsupportedMode        = errors.New("unsupported anchor publisher mode")
	ErrIPFSNotAvailable       = errors.New("IPFS backend not available")
)

// PublisherMode defines the anchor publishing mode.
type PublisherMode string

const (
	ModeAll         PublisherMode = "all"         // Publish to all configured backends
	ModeDesignated  PublisherMode = "designated"  // Publish to designated publishers only
	ModeExternal    PublisherMode = "external"    // External publisher (not managed by this node)
)

// AnchorPublisherConfig defines the configuration for anchor publishing.
type AnchorPublisherConfig struct {
	Mode                PublisherMode  `yaml:"mode" json:"mode"`
	DesignatedPublishers []string      `yaml:"designated_publishers" json:"designated_publishers"` // Peer IDs
	MinRedundancy       int            `yaml:"min_redundancy" json:"min_redundancy"`              // Minimum backends to succeed

	// Filesystem backend
	FilesystemPath string `yaml:"filesystem_path" json:"filesystem_path"`

	// IPFS backend
	IPFSEnabled    bool   `yaml:"ipfs_enabled" json:"ipfs_enabled"`
	IPFSGateway    string `yaml:"ipfs_gateway" json:"ipfs_gateway"`       // e.g., "/ip4/127.0.0.1/tcp/5001"
	IPFSHashFunc   string `yaml:"ipfs_hash_func" json:"ipfs_hash_func"`   // "blake3-256" or "sha2-256"

	// S3 backend (future)
	S3Enabled bool `yaml:"s3_enabled" json:"s3_enabled"`
}

// DefaultAnchorPublisherConfig returns a default configuration.
func DefaultAnchorPublisherConfig() AnchorPublisherConfig {
	return AnchorPublisherConfig{
		Mode:           ModeAll,
		MinRedundancy:  1, // Default to 1 for single publisher (filesystem)
		FilesystemPath: "./anchors",
		IPFSEnabled:    false,
		IPFSHashFunc:   "blake3-256",
	}
}

// BlockPublisher defines the interface for publishing blocks.
type BlockPublisher interface {
	Publish(ctx context.Context, block *chain.Block) ([]string, error)
	Close() error
}

// AnchorPublisher manages multiple block publishers.
type AnchorPublisher struct {
	mu        sync.RWMutex
	config    AnchorPublisherConfig
	publishers []BlockPublisher
	closed    bool
}

// NewAnchorPublisher creates a new anchor publisher with the given configuration.
func NewAnchorPublisher(cfg AnchorPublisherConfig) (*AnchorPublisher, error) {
	ap := &AnchorPublisher{
		config:     cfg,
		publishers: make([]BlockPublisher, 0),
	}

	// Initialize filesystem publisher (always enabled if path set)
	if cfg.FilesystemPath != "" {
		fsPub, err := NewFilesystemPublisher(cfg.FilesystemPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create filesystem publisher: %w", err)
		}
		ap.publishers = append(ap.publishers, fsPub)
	}

	// Initialize IPFS publisher if enabled
	if cfg.IPFSEnabled {
		ipfsPub, err := NewIPFSPublisher(cfg.IPFSGateway, cfg.IPFSHashFunc)
		if err != nil {
			// IPFS is optional - log warning but don't fail
			fmt.Printf("Warning: IPFS publisher not available: %v\n", err)
		} else {
			ap.publishers = append(ap.publishers, ipfsPub)
		}
	}

	if len(ap.publishers) == 0 {
		return nil, ErrPublisherNotConfigured
	}

	return ap, nil
}

// Publish publishes a block to all configured backends.
// Returns the list of external anchor URIs/CIDs.
func (ap *AnchorPublisher) Publish(ctx context.Context, block *chain.Block) ([]string, error) {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	if ap.closed {
		return nil, errors.New("anchor publisher closed")
	}

	var anchors []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, len(ap.publishers))

	for _, pub := range ap.publishers {
		wg.Add(1)
		go func(p BlockPublisher) {
			defer wg.Done()
			uris, err := p.Publish(ctx, block)
			mu.Lock()
			anchors = append(anchors, uris...)
			mu.Unlock()
			if err != nil {
				errChan <- err
			}
		}(pub)
	}

	wg.Wait()
	close(errChan)

	// Check if we met minimum redundancy
	successCount := len(anchors)
	if successCount < ap.config.MinRedundancy {
		// Collect errors
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		return anchors, fmt.Errorf("anchor redundancy not met: got %d, need %d; errors: %v", successCount, ap.config.MinRedundancy, errs)
	}

	return anchors, nil
}

// Close closes all publishers.
func (ap *AnchorPublisher) Close() error {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	if ap.closed {
		return nil
	}
	ap.closed = true

	var errs []error
	for _, pub := range ap.publishers {
		if err := pub.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing publishers: %v", errs)
	}
	return nil
}

// FilesystemPublisher publishes blocks to the local filesystem.
type FilesystemPublisher struct {
	basePath string
	mu       sync.Mutex
}

// NewFilesystemPublisher creates a new filesystem publisher.
func NewFilesystemPublisher(basePath string) (*FilesystemPublisher, error) {
	// Convert to absolute path for reliability
	absPath, err := filepath.Abs(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve anchor path: %w", err)
	}
	// Ensure directory exists
	if err := os.MkdirAll(absPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create anchor directory: %w", err)
	}
	return &FilesystemPublisher{basePath: absPath}, nil
}

// Publish writes the block to a CBOR file.
func (fp *FilesystemPublisher) Publish(ctx context.Context, block *chain.Block) ([]string, error) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	// Marshal block to canonical CBOR
	data, err := chain.MarshalCBOR(block)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal block: %w", err)
	}

	// Filename: block_<index>.cbor
	filename := fmt.Sprintf("block_%d.cbor", block.Index)
	path := filepath.Join(fp.basePath, filename)

	// Write atomically using temp file + rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write block file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return nil, fmt.Errorf("failed to rename block file: %w", err)
	}

	// Return file:// URI
	absPath, _ := filepath.Abs(path)
	return []string{"file://" + absPath}, nil
}

// Close is a no-op for filesystem publisher.
func (fp *FilesystemPublisher) Close() error {
	return nil
}

// IPFSPublisher publishes blocks to IPFS.
type IPFSPublisher struct {
	gateway  string
	hashFunc uint64 // multihash code
}

// NewIPFSPublisher creates a new IPFS publisher.
func NewIPFSPublisher(gateway, hashFunc string) (*IPFSPublisher, error) {
	var mhCode uint64
	switch hashFunc {
	case "blake3-256":
		mhCode = 0xb240 // blake3-256 multihash code (hypothetical)
	case "sha2-256":
		mhCode = multihash.SHA2_256
	default:
		return nil, fmt.Errorf("unsupported IPFS hash function: %s", hashFunc)
	}

	// TODO: Implement actual IPFS client connection
	// For now, return a publisher that simulates IPFS publishing
	return &IPFSPublisher{
		gateway:  gateway,
		hashFunc: mhCode,
	}, nil
}

// Publish simulates publishing to IPFS (returns a mock CID).
// In production, this would use the IPFS HTTP API or libp2p.
func (ip *IPFSPublisher) Publish(ctx context.Context, block *chain.Block) ([]string, error) {
	// Marshal block to canonical CBOR
	data, err := chain.MarshalCBOR(block)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal block: %w", err)
	}

	// Compute CID (using BLAKE3 for content addressing)
	hash := blake3.Sum256(data)
	// Create a CIDv1 with raw codec and blake3-256 hash
	cidBuilder := cid.V1Builder{
		Codec:    cid.Raw,
		MhType:   multihash.SHA2_256, // Using SHA2-256 as blake3 may not be in multihash
		MhLength: -1,
	}
	c, err := cidBuilder.Sum(hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create CID: %w", err)
	}

	// Return IPFS gateway URI
	uri := fmt.Sprintf("ipfs://%s", c.String())
	return []string{uri}, nil
}

// Close is a no-op for IPFS publisher.
func (ip *IPFSPublisher) Close() error {
	return nil
}

// ComputeAnchorCID computes the CID for a block (for verification).
func ComputeAnchorCID(block *chain.Block) (string, error) {
	data, err := chain.MarshalCBOR(block)
	if err != nil {
		return "", err
	}
	hash := blake3.Sum256(data)
	cidBuilder := cid.V1Builder{
		Codec:    cid.Raw,
		MhType:   multihash.SHA2_256,
		MhLength: -1,
	}
	c, err := cidBuilder.Sum(hash[:])
	if err != nil {
		return "", err
	}
	return c.String(), nil
}

// VerifyAnchorCID verifies that a block matches the given CID.
func VerifyAnchorCID(block *chain.Block, expectedCID string) (bool, error) {
	cid, err := ComputeAnchorCID(block)
	if err != nil {
		return false, err
	}
	return cid == expectedCID, nil
}

// S3Publisher publishes blocks to S3-compatible storage (placeholder).
type S3Publisher struct {
	bucket   string
	region   string
	endpoint string
}

// NewS3Publisher creates a new S3 publisher (not yet implemented).
func NewS3Publisher(bucket, region, endpoint string) (*S3Publisher, error) {
	return &S3Publisher{bucket: bucket, region: region, endpoint: endpoint}, nil
}

// Publish is not yet implemented.
func (sp *S3Publisher) Publish(ctx context.Context, block *chain.Block) ([]string, error) {
	return nil, errors.New("S3 publisher not yet implemented")
}

// Close is a no-op.
func (sp *S3Publisher) Close() error {
	return nil
}