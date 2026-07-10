// BoltDB storage backend for Gleipnir.
package storage

import (
	"github.com/had-nu/gleipnir/pkg/consensus"
)

// Open creates a new BoltDB storage at the given path.
func Open(path string) (consensus.EngineStorage, error) {
	return NewBoltStorage(path)
}