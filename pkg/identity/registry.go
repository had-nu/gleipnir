package identity

import (
	"sync"

	"go.etcd.io/bbolt"
)

const registryBucket = "identities"

var (
	ErrNotFound      = &NotFoundError{}
	ErrInvalidKeySize = &KeySizeError{}
)

type NotFoundError struct{}

func (e *NotFoundError) Error() string { return "identity not found in registry" }

type KeySizeError struct{}

func (e *KeySizeError) Error() string { return "invalid key size" }

type Registry struct {
	db    *bbolt.DB
	cache map[string]*PublicKeyData
	mu    sync.RWMutex
}

type PublicKeyData struct {
	Data   []byte
	RootID string
}

func NewRegistry() *Registry {
	return &Registry{
		cache: make(map[string]*PublicKeyData),
	}
}

func (r *Registry) Open(db *bbolt.DB) error {
	r.db = db
	return db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(registryBucket))
		return err
	})
}

func (r *Registry) Register(rootID string, pubKey []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(pubKey) != 1952 {
		return ErrInvalidKeySize
	}

	r.cache[rootID] = &PublicKeyData{Data: pubKey, RootID: rootID}

	if r.db != nil {
		return r.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket([]byte(registryBucket))
			return b.Put([]byte(rootID), pubKey)
		})
	}
	return nil
}

func (r *Registry) Lookup(rootID string) ([]byte, error) {
	r.mu.RLock()
	if cached, ok := r.cache[rootID]; ok {
		r.mu.RUnlock()
		return cached.Data, nil
	}
	r.mu.RUnlock()

	if r.db != nil {
		var pubKey []byte
		err := r.db.View(func(tx *bbolt.Tx) error {
			b := tx.Bucket([]byte(registryBucket))
			if b == nil {
				return ErrNotFound
			}
			pubKey = b.Get([]byte(rootID))
			if pubKey == nil {
				return ErrNotFound
			}
			return nil
		})
		if err == nil && pubKey != nil {
			r.mu.Lock()
			r.cache[rootID] = &PublicKeyData{Data: pubKey, RootID: rootID}
			r.mu.Unlock()
			return pubKey, nil
		}
	}

	return nil, ErrNotFound
}

func (r *Registry) Exists(rootID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.cache[rootID]; ok {
		return true
	}
	if r.db != nil {
		var found bool
		_ = r.db.View(func(tx *bbolt.Tx) error {
			b := tx.Bucket([]byte(registryBucket))
			if b != nil && b.Get([]byte(rootID)) != nil {
				found = true
			}
			return nil
		})
		return found
	}
	return false
}

// GetAll returns all registered public keys
func (r *Registry) GetAll() [][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([][]byte, 0, len(r.cache))
	for _, v := range r.cache {
		result = append(result, v.Data)
	}
	return result
}