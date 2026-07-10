// BoltDB implementation of consensus.EngineStorage.
package storage

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/smt"
	"github.com/had-nu/gleipnir/pkg/state"
	"go.etcd.io/bbolt"
)

var (
	bucketState     = []byte("state")
	bucketBlocks    = []byte("blocks")
	bucketPending   = []byte("pending")
	bucketAnchored  = []byte("anchored")
	bucketSMT       = []byte("smt")
	bucketSubChains = []byte("subchains")
	bucketMeta      = []byte("meta")
	bucketSchema    = []byte("schema")
)

const schemaVersion = 1

var ErrNotFound = errors.New("not found")

type BoltStorage struct {
	db *bbolt.DB
}

func NewBoltStorage(path string) (*BoltStorage, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 5})
	if err != nil {
		return nil, fmt.Errorf("open bolt: %w", err)
	}

	s := &BoltStorage{db: db}
	if err := s.initBuckets(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *BoltStorage) initBuckets() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{
			bucketState, bucketBlocks, bucketPending, bucketAnchored,
			bucketSMT, bucketSubChains, bucketMeta, bucketSchema,
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("create bucket %s: %w", b, err)
			}
		}
		return nil
	})
}

func (s *BoltStorage) migrate() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSchema)
		if b == nil {
			return nil
		}
		v := b.Get([]byte("version"))
		if v == nil {
			return b.Put([]byte("version"), itob(schemaVersion))
		}
		cur := binary.BigEndian.Uint64(v)
		if cur < schemaVersion {
			return b.Put([]byte("version"), itob(schemaVersion))
		}
		return nil
	})
}

func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func (s *BoltStorage) Close() error {
	return s.db.Close()
}

// --- State ---

func (s *BoltStorage) SaveState(ctx context.Context, st state.NetworkState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketState).Put([]byte("current"), data)
	})
}

func (s *BoltStorage) LoadState(ctx context.Context) (state.NetworkState, bool, error) {
	var st state.NetworkState
	err := s.db.View(func(tx *bbolt.Tx) error {
		data := tx.Bucket(bucketState).Get([]byte("current"))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &st)
	})
	if errors.Is(err, ErrNotFound) {
		return state.NetworkState{}, false, nil
	}
	return st, true, err
}

// --- Blocks ---

func (s *BoltStorage) SaveBlock(ctx context.Context, block chain.Block) error {
	data, err := json.Marshal(block)
	if err != nil {
		return err
	}
	key := itob(block.Index)
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketBlocks).Put(key, data)
	})
}

func (s *BoltStorage) LoadBlocks(ctx context.Context) ([]chain.Block, error) {
	var blocks []chain.Block
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var block chain.Block
			if err := json.Unmarshal(v, &block); err != nil {
				return err
			}
			blocks = append(blocks, block)
		}
		return nil
	})
	return blocks, err
}

func (s *BoltStorage) GetBlock(ctx context.Context, index uint64) (*chain.Block, error) {
	var block chain.Block
	err := s.db.View(func(tx *bbolt.Tx) error {
		data := tx.Bucket(bucketBlocks).Get(itob(index))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &block)
	})
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return &block, err
}

// --- Pending ---

func (s *BoltStorage) SavePending(ctx context.Context, entries []chain.ProvenanceEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketPending).Put([]byte("current"), data)
	})
}

func (s *BoltStorage) LoadPending(ctx context.Context) ([]chain.ProvenanceEntry, error) {
	var entries []chain.ProvenanceEntry
	err := s.db.View(func(tx *bbolt.Tx) error {
		data := tx.Bucket(bucketPending).Get([]byte("current"))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &entries)
	})
	return entries, err
}

// --- Anchored ---

func (s *BoltStorage) SaveAnchored(ctx context.Context, hash [32]byte, proof *chain.AnchorProof) error {
	data, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketAnchored).Put(hash[:], data)
	})
}

func (s *BoltStorage) LoadAnchored(ctx context.Context) (map[[32]byte]*chain.AnchorProof, error) {
	anchored := make(map[[32]byte]*chain.AnchorProof)
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAnchored)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var hash [32]byte
			copy(hash[:], k)
			var proof chain.AnchorProof
			if err := json.Unmarshal(v, &proof); err != nil {
				return err
			}
			anchored[hash] = &proof
		}
		return nil
	})
	return anchored, err
}

// --- SMT ---

func (s *BoltStorage) SaveSMT(ctx context.Context, tree interface{}) error {
	t, ok := tree.(*smt.SparseMerkleTree)
	if !ok {
		return errors.New("invalid SMT type")
	}
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSMT).Put([]byte("tree"), data)
	})
}

func (s *BoltStorage) LoadSMT(ctx context.Context) (interface{}, error) {
	var tree smt.SparseMerkleTree
	err := s.db.View(func(tx *bbolt.Tx) error {
		data := tx.Bucket(bucketSMT).Get([]byte("tree"))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, &tree)
	})
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return &tree, err
}

// --- Sub-chains ---

func (s *BoltStorage) SaveSubChain(ctx context.Context, id chain.SubChainID, sc interface{}) error {
	data, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSubChains).Put(id[:], data)
	})
}

func (s *BoltStorage) LoadSubChains(ctx context.Context) (map[chain.SubChainID]interface{}, error) {
	subChains := make(map[chain.SubChainID]interface{})
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSubChains)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var id chain.SubChainID
			copy(id[:], k)
			var sc consensus.SubChainManager
			if err := json.Unmarshal(v, &sc); err != nil {
				return err
			}
			subChains[id] = &sc
		}
		return nil
	})
	return subChains, err
}

// --- Meta ---

func (s *BoltStorage) SaveMeta(ctx context.Context, key string, value []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketMeta).Put([]byte(key), value)
	})
}

func (s *BoltStorage) LoadMeta(ctx context.Context, key string) ([]byte, error) {
	var val []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		val = tx.Bucket(bucketMeta).Get([]byte(key))
		if val == nil {
			return ErrNotFound
		}
		return nil
	})
	return val, err
}