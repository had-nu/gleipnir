package consensus

import (
	"encoding/binary"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/smt"
)

var (
	ErrSubChainNotFound = errors.New("sub-chain not found")
	ErrSubChainExists   = errors.New("sub-chain already registered")
)

type SubChainManager struct {
	mu     sync.Mutex
	engine *Engine
	chains map[chain.SubChainID]*subChain
}

type subChain struct {
	desc    chain.SubChainDescriptor
	st      *smt.SparseMerkleTree
	anchors []chain.CrossChainAnchor
	pending []chain.ProvenanceEntry
}

func NewSubChainManager(engine *Engine) *SubChainManager {
	return &SubChainManager{
		engine: engine,
		chains: make(map[chain.SubChainID]*subChain),
	}
}

func (m *SubChainManager) newSMT() *smt.SparseMerkleTree {
	return smt.New(m.engine.cfg.SMTDepth)
}

func (m *SubChainManager) Register(name string, owner []byte) (chain.SubChainID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UnixNano()
	seed := append([]byte(name), owner...)
	seed = binary.LittleEndian.AppendUint64(seed, uint64(now))
	var id chain.SubChainID
	copy(id[:], identity.Hash(seed))

	if _, ok := m.chains[id]; ok {
		return chain.SubChainID{}, ErrSubChainExists
	}

	st := m.newSMT()
	genesis := st.Root()

	m.chains[id] = &subChain{
		desc: chain.SubChainDescriptor{
			ID:        id,
			Name:      name,
			Owner:     owner,
			Genesis:   genesis,
			CreatedAt: now,
			Active:    true,
		},
		st:      st,
		anchors: make([]chain.CrossChainAnchor, 0),
	}

	log.Printf("Sub-chain registered: %s (name=%s)", id.String(), name)
	return id, nil
}

func (m *SubChainManager) Descriptor(id chain.SubChainID) (*chain.SubChainDescriptor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sc, ok := m.chains[id]
	if !ok {
		return nil, ErrSubChainNotFound
	}
	desc := sc.desc
	return &desc, nil
}

func (m *SubChainManager) Submit(id chain.SubChainID, entry chain.ProvenanceEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sc, ok := m.chains[id]
	if !ok {
		return ErrSubChainNotFound
	}
	sc.pending = append(sc.pending, entry)
	return nil
}

func (m *SubChainManager) Anchor(id chain.SubChainID) error {
	m.mu.Lock()
	sc, ok := m.chains[id]
	if !ok {
		m.mu.Unlock()
		return ErrSubChainNotFound
	}

	for _, entry := range sc.pending {
		var h [32]byte
		copy(h[:], entry.Hash[:])
		sc.st.Insert(h[:], entry.Hash[:])
	}
	sc.pending = nil

	stateRoot := sc.st.Root()

	anchorData := append(id[:], stateRoot[:]...)
	var anchorHash [32]byte
	copy(anchorHash[:], identity.Hash(anchorData))

	now := time.Now().UnixNano()
	var prevAnchorHash [32]byte
	if len(sc.anchors) > 0 {
		prevAnchorHash = sc.anchors[len(sc.anchors)-1].StateRoot
	}

	anch := chain.CrossChainAnchor{
		SubChainID:     id,
		StateRoot:      stateRoot,
		PrevAnchorHash: prevAnchorHash,
		SubChainHeight: uint64(len(sc.anchors)),
		Timestamp:      now,
	}
	sc.anchors = append(sc.anchors, anch)
	anchorHeight := len(sc.anchors)
	m.mu.Unlock()

	entry := chain.ProvenanceEntry{
		Hash:      anchorHash,
		Submitter: sc.desc.Owner,
		Timestamp: now,
		Label:     "subchain:anchor",
	}
	if err := m.engine.Enqueue(entry); err != nil {
		log.Printf("Sub-chain %s anchor enqueue failed: %v", id.String(), err)
	}

	log.Printf("Sub-chain %s anchored at height %d root=%x",
		id.String(), anchorHeight, stateRoot[:8])
	return nil
}

func (m *SubChainManager) Prove(id chain.SubChainID, entryHash [32]byte) (*chain.CrossChainProof, error) {
	m.mu.Lock()
	sc, ok := m.chains[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrSubChainNotFound
	}

	subProof, err := sc.st.Prove(entryHash[:])
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	subRoot := sc.st.Root()

	if len(sc.anchors) == 0 {
		m.mu.Unlock()
		return nil, errors.New("sub-chain has no anchors")
	}
	m.mu.Unlock()

	anchorData := append(id[:], subRoot[:]...)
	var anchorHash [32]byte
	copy(anchorHash[:], identity.Hash(anchorData))

	parentProof, err := m.engine.ProveSMT(anchorHash[:])
	if err != nil {
		return nil, err
	}
	parentRoot := m.engine.GetStateRoot()

	ap, ok := m.engine.LookupHash(anchorHash)
	if !ok {
		return nil, errors.New("anchor not yet committed in parent chain")
	}

	proof := &chain.CrossChainProof{
		EntryHash:     entryHash,
		SubChainRoot:  subRoot,
		SubChainProof: subProof,
		AnchorHash:    anchorHash,
		AnchorBlock:   ap.BlockIndex,
		ParentProof:   parentProof,
	}
	copy(proof.ParentRoot[:], parentRoot)
	return proof, nil
}

func (m *SubChainManager) VerifyCrossChain(proof *chain.CrossChainProof, parentRoot [32]byte) bool {
	smtVerifier := smt.New(256)

	if !smtVerifier.Verify(proof.EntryHash[:], proof.EntryHash[:], proof.SubChainRoot, proof.SubChainProof) {
		return false
	}

	if !smtVerifier.Verify(proof.AnchorHash[:], proof.AnchorHash[:], parentRoot, proof.ParentProof) {
		return false
	}

	return true
}
