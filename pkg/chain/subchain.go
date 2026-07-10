package chain

import "encoding/hex"

type SubChainID [32]byte

func (id SubChainID) String() string {
	return hex.EncodeToString(id[:])
}

type SubChainDescriptor struct {
	ID        SubChainID
	Name      string
	Owner     []byte
	Genesis   [32]byte
	CreatedAt int64
	Active    bool
}

type CrossChainAnchor struct {
	SubChainID     SubChainID
	StateRoot      [32]byte
	PrevAnchorHash [32]byte
	SubChainHeight uint64
	Timestamp      int64
}

type CrossChainProof struct {
	EntryHash     [32]byte
	SubChainRoot  [32]byte
	SubChainProof [][32]byte
	AnchorHash    [32]byte
	AnchorBlock   uint64
	ParentRoot    [32]byte
	ParentProof   [][32]byte
}
