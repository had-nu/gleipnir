// IPC identity — uID0 soulbound token. Gleipnir reference implementation.
package identity

import (
	"crypto/rand"
	"encoding/hex"
)

type UIDZeroSoulbound struct {
	RootID              []byte   `cbor:"0,keyasint"`
	FEntropy            []byte   `cbor:"1,keyasint"`
	GenesisHash         []byte   `cbor:"2,keyasint"`
	FounderMerkleProofs [][]byte `cbor:"3,keyasint"`
	SigRecovery         []byte   `cbor:"4,keyasint"`
	SigUpdate           []byte   `cbor:"5,keyasint"`
	SigAudit            []byte   `cbor:"6,keyasint"`
	ReputationSum       uint64   `cbor:"7,keyasint"`
	SiderealTime        string   `cbor:"8,keyasint"`
	CycleIndex          uint64   `cbor:"9,keyasint"`
	GeneratedAt         int64    `cbor:"10,keyasint"`
	MerkleRoot          []byte   `cbor:"11,keyasint,omitempty"`
	MerkleProof         [][]byte `cbor:"12,keyasint,omitempty"`
	Simulated           bool     `cbor:"13,keyasint"`
	FinalDigest         []byte   `cbor:"14,keyasint"`
	PublicKey           []byte   `cbor:"15,keyasint"`
	SecretKey           []byte   `cbor:"16,keyasint,omitempty"`
	ContractHash        []byte   `cbor:"17,keyasint,omitempty"`
}

func NewUIDZero(randSeed string, simulated bool) *UIDZeroSoulbound {
	seed := make([]byte, 32)
	copy(seed, []byte(randSeed))

	pk, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		pk = make([]byte, 32)
		sk = make([]byte, 32)
	}

	uid := &UIDZeroSoulbound{
		RootID:      seed[:16],
		FEntropy:    seed[16:],
		GenesisHash: []byte(hex.EncodeToString(seed)),
		CycleIndex:  0,
		GeneratedAt: generateTimestamp(),
		Simulated:   simulated,
		PublicKey:   pk,
		SecretKey:   sk,
	}
	return uid
}

func (u *UIDZeroSoulbound) ID() string {
	return hex.EncodeToString(u.RootID)
}

func generateTimestamp() int64 {
	return 1700000000
}
