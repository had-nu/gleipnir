// Mandate resolution — 3CP v2.0 §13.
//
// A mandate is an ordinary provenance entry labelled "3cp:mandate:v1"; the entry hash
// is the key and the canonical CBOR body is the value. Resolving a mandate therefore
// means finding the body the chain anchored, not reading a block header field.
//
// SPEC-GLEIPNIR-GAPS-V2.1 §2.1.1 sketches a resolver over `state.Blocks`, unmarshalling
// `entry.Hash` as if it were the mandate body. Neither holds: NetworkState carries no
// block list, and a ProvenanceEntry anchors only a hash and a label, so the body has to
// be retained when the mandate is admitted — the same arrangement key rotation uses.
package validation

import (
	"sort"
	"sync"

	"github.com/had-nu/gleipnir/pkg/chain"
)

// MandateResolver answers "which mandates were in force at time T", over the set of
// mandate bodies the chain has anchored.
//
// It is safe for concurrent use: submission-time validation and auditor-driven
// verification reach it from different goroutines.
type MandateResolver struct {
	mu sync.RWMutex
	// mandates is keyed by mandate ID. Bodies are retained because a ProvenanceEntry
	// anchors only the hash, so the body cannot be recovered from the chain later.
	mandates map[[32]byte]*chain.MandateEntry
}

// NewMandateResolver creates a resolver over a snapshot of known mandates.
func NewMandateResolver(mandates []chain.MandateEntry) *MandateResolver {
	r := &MandateResolver{mandates: make(map[[32]byte]*chain.MandateEntry, len(mandates))}
	for i := range mandates {
		// Put only rejects a nil mandate, which cannot occur here.
		_ = r.Put(&mandates[i])
	}
	return r
}

// Put records a mandate body. The ID is recomputed rather than trusted, so a body whose
// stored ID does not match its contents cannot enter the resolver under a false name.
func (r *MandateResolver) Put(mandate *chain.MandateEntry) error {
	if mandate == nil {
		return ErrMandateNotFound
	}
	clone := *mandate
	clone.ID = clone.MandateID()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.mandates[clone.ID] = &clone
	return nil
}

// GetMandateByID returns the mandate with the given identifier.
func (r *MandateResolver) GetMandateByID(id [32]byte) (*chain.MandateEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.mandates[id]
	if !ok {
		return nil, false
	}
	clone := *m
	return &clone, true
}

// All returns every known mandate, ordered by ID so that reports are reproducible.
func (r *MandateResolver) All() []*chain.MandateEntry {
	r.mu.RLock()
	out := make([]*chain.MandateEntry, 0, len(r.mandates))
	for _, m := range r.mandates {
		clone := *m
		out = append(out, &clone)
	}
	r.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		return bytesLess(out[i].ID[:], out[j].ID[:])
	})
	return out
}

// GetActiveMandates returns every mandate in force at the given UnixNano timestamp.
//
// Only the latest version of each lineage is returned: when a mandate supersedes an
// earlier one, only the newest applies, and an auditor asking "what was required at T"
// must not be shown the requirement it replaced.
func (r *MandateResolver) GetActiveMandates(timestamp int64) ([]*chain.MandateEntry, error) {
	all := r.All()

	// Drop any mandate that a newer version in the same lineage supersedes.
	superseded := make(map[[32]byte]bool, len(all))
	for _, m := range all {
		if m.Supersedes != ([32]byte{}) {
			superseded[m.Supersedes] = true
		}
	}

	active := make([]*chain.MandateEntry, 0, len(all))
	for _, m := range all {
		if superseded[m.ID] {
			continue
		}
		if m.IsActiveAt(timestamp) {
			active = append(active, m)
		}
	}
	return active, nil
}

// GetMandateByReference resolves the mandate an entry claims to satisfy. A nil
// reference means the entry made no compliance claim, which is not an error.
func (r *MandateResolver) GetMandateByReference(ref *[32]byte) (*chain.MandateEntry, bool) {
	if ref == nil {
		return nil, false
	}
	return r.GetMandateByID(*ref)
}

// GetLatestVersion returns the highest-versioned mandate in the lineage identified by
// root, where root is the first version's ID.
func (r *MandateResolver) GetLatestVersion(root [32]byte) (*chain.MandateEntry, bool) {
	all := r.All()

	var latest *chain.MandateEntry
	for _, m := range all {
		if m.ID != root && m.PrevVersion != root && m.Supersedes != root {
			continue
		}
		if latest == nil || m.Version > latest.Version {
			latest = m
		}
	}
	return latest, latest != nil
}

// ErrMandateNotFound is declared in errors_v2.go alongside the other mandate errors.

func bytesLess(a, b []byte) bool {
	for i := range a {
		if i >= len(b) {
			return false
		}
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
