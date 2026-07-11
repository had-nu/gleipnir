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
	VRFPublicKey        []byte   `cbor:"18,keyasint,omitempty"` // VRF public key for proposer election
	VRFSecretKey        []byte   `cbor:"19,keyasint,omitempty"` // VRF secret key (never exported)
}

func NewUIDZero(randSeed string, simulated bool) *UIDZeroSoulbound {
	seed := make([]byte, 32)
	copy(seed, []byte(randSeed))

	pk, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		pk = make([]byte, 32)
		sk = make([]byte, 32)
	}

	// Generate VRF keypair
	vrfSK, vrfPK, _ := GenerateVRFKeyPair()

	uid := &UIDZeroSoulbound{
		RootID:       seed[:16],
		FEntropy:     seed[16:],
		GenesisHash:  []byte(hex.EncodeToString(seed)),
		CycleIndex:   0,
		GeneratedAt:  generateTimestamp(),
		Simulated:    simulated,
		PublicKey:    pk,
		SecretKey:    sk,
		VRFPublicKey: vrfPK.Bytes(),
		VRFSecretKey: vrfSK.Bytes(),
	}
	return uid
}

func (u *UIDZeroSoulbound) ID() string {
	return hex.EncodeToString(u.RootID)
}

// VRFProve computes a VRF proof for the given alpha using this identity's VRF secret key.
func (u *UIDZeroSoulbound) VRFProve(alpha []byte) (*VRFProof, error) {
	sk, err := VRFPrivateKeyFromBytes(u.VRFSecretKey)
	if err != nil {
		return nil, err
	}
	return sk.Prove(alpha)
}

// VRFVerifyProof verifies a VRF proof for the given alpha against this identity's VRF public key.
func (u *UIDZeroSoulbound) VRFVerifyProof(alpha []byte, proof *VRFProof) ([]byte, error) {
	pk, err := VRFPublicKeyFromBytes(u.VRFPublicKey)
	if err != nil {
		return nil, err
	}
	return pk.Verify(alpha, proof)
}

// VRFPublicKeyObject returns the VRF public key as an object.
func (u *UIDZeroSoulbound) VRFPublicKeyObject() (*VRFPublicKey, error) {
	return VRFPublicKeyFromBytes(u.VRFPublicKey)
}

func generateTimestamp() int64 {
	return 1700000000
}
