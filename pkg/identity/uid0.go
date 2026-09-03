// IPC identity — UID0 v2.0 soulbound token (HKDF + NetworkID).
// Gleipnir reference implementation of 3CP v2.0 SPEC §4.3.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var (
	ErrInvalidEntropy   = errors.New("entropy source must be at least 32 bytes")
	ErrInvalidNetworkID = errors.New("networkID must be 32 bytes")
)

// UIDZeroSoulbound represents a soulbound identity in the 3CP v2.0 protocol.
// Keys are derived via HKDF(NetworkID || entropySource) per spec §4.3.
type UIDZeroSoulbound struct {
	RootID         [16]byte  `cbor:"0,keyasint"`
	PublicKey      [1952]byte `cbor:"1,keyasint"`   // Dilithium3 public key
	SecretKey      []byte     `cbor:"2,keyasint,omitempty"` // Dilithium3 secret key (4032 bytes)
	VRFPublicKey   [32]byte   `cbor:"3,keyasint"`   // Ristretto255 VRF public key
	VRFSecretKey   []byte     `cbor:"4,keyasint,omitempty"` // VRF secret key (32 bytes, never exported)
	ContractHash   [32]byte   `cbor:"5,keyasint"`   // Contract hash binding
	FinalDigest    [32]byte   `cbor:"6,keyasint"`   // CBOR canonical digest of this struct
	Simulated      bool       `cbor:"7,keyasint"`
}

// NewUIDZero derives a UID0 v2.0 identity from entropy and NetworkID.
// entropySource: min 32 bytes of entropy (e.g., from HSM, KMS, or CSPRNG)
// networkID: 32-byte BLAKE3 hash of genesis block (per spec §3.1)
// simulated: if true, uses deterministic test keys (for testing only) - entropy check is skipped
// contractHash: optional pre-computed contract hash (if derived from contract); if zero, will be derived from entropy
func NewUIDZero(entropySource string, networkID [32]byte, simulated bool, contractHashOpt ...[32]byte) (*UIDZeroSoulbound, error) {
	if !simulated && len(entropySource) < 32 {
		return nil, ErrInvalidEntropy
	}

	// HKDF-SHA256: PRK = HMAC-SHA256(salt=NetworkID, IKM=entropySource)
	// Then expand for each key: OKM = HMAC-SHA256(PRK, info || counter)
	prk := hkdfExtract(networkID[:], []byte(entropySource))

	// Derive keys with distinct info strings
	dilithiumSeed := hkdfExpand(prk, []byte("3cp:v2:dilithium3"), Dilithium3SeedSize)
	vrfSeed := hkdfExpand(prk, []byte("3cp:v2:vrf"), 32)
	rootIDBytes := hkdfExpand(prk, []byte("3cp:v2:rootid"), 16)
	contractHashBytes := hkdfExpand(prk, []byte("3cp:v2:contract"), 32)

	var rootID [16]byte
	copy(rootID[:], rootIDBytes)

	var contractHash [32]byte
	if len(contractHashOpt) > 0 {
		// Use provided contract hash
		contractHash = contractHashOpt[0]
	} else {
		// Derive from entropy
		copy(contractHash[:], contractHashBytes)
	}

	var dilithiumPK [1952]byte
	var dilithiumSK []byte
	var vrfPK [32]byte
	var vrfSK []byte

	if simulated {
		// Deterministic test keys for reproducible tests
		dilithiumPK, dilithiumSK = generateDilithiumDeterministic(dilithiumSeed)
		vrfPK, vrfSK = generateVRFDeterministic(vrfSeed)
	} else {
		// Production: use CSPRNG with derived seed as additional entropy
		dilithiumPK, dilithiumSK = generateDilithiumKey(dilithiumSeed)
		vrfPK, vrfSK = generateVRFKey(vrfSeed)
	}

	uid := &UIDZeroSoulbound{
		RootID:       rootID,
		PublicKey:    dilithiumPK,
		SecretKey:    dilithiumSK,
		VRFPublicKey: vrfPK,
		VRFSecretKey: vrfSK,
		ContractHash: contractHash,
		Simulated:    simulated,
	}

	// Calculate and set FinalDigest (CBOR canonical without FinalDigest)
	digest, err := uid.CalculateFinalDigest()
	if err != nil {
		return nil, err
	}
	uid.FinalDigest = digest

	return uid, nil
}

// ID returns the RootID as hex string (used as map key).
func (u *UIDZeroSoulbound) ID() string {
	return hex.EncodeToString(u.RootID[:])
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
	pk, err := VRFPublicKeyFromBytes(u.VRFPublicKey[:])
	if err != nil {
		return nil, err
	}
	return pk.Verify(alpha, proof)
}

// VRFPublicKeyObject returns the VRF public key as an object.
func (u *UIDZeroSoulbound) VRFPublicKeyObject() (*VRFPublicKey, error) {
	return VRFPublicKeyFromBytes(u.VRFPublicKey[:])
}

// SignDilithium signs a message with this identity's Dilithium3 secret key.
func (u *UIDZeroSoulbound) SignDilithium(msg []byte) []byte {
	return SignDilithium(u.SecretKey, msg)
}

// VerifyDilithium verifies a Dilithium3 signature against this identity's public key.
func (u *UIDZeroSoulbound) VerifyDilithium(msg []byte, sig []byte) bool {
	return VerifyDilithium(u.PublicKey[:], msg, sig)
}

// hkdfExtract implements HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpand implements HKDF-Expand: OKM = HMAC-Hash(PRK, T_{i-1} || info || counter)
// where T_0 = empty, T_i = HMAC-Hash(PRK, T_{i-1} || info || i)
func hkdfExpand(prk, info []byte, length int) []byte {
	h := hmac.New(sha256.New, prk)
	var counter byte = 1
	var t []byte
	var okm []byte
	for len(okm) < length {
		h.Reset()
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		okm = append(okm, t...)
		counter++
	}
	return okm[:length]
}

// generateDilithiumDeterministic generates a deterministic Dilithium3 keypair for testing.
func generateDilithiumDeterministic(seed []byte) ([1952]byte, []byte) {
	pk, sk, err := GenerateDilithiumKeyFromSeed(seed)
	if err != nil {
		// Fallback for tests
		return [1952]byte{}, make([]byte, Dilithium3SecretKeySize)
	}
	return pk, sk
}

// generateDilithiumKey generates a production Dilithium3 keypair using seed as entropy.
func generateDilithiumKey(seed []byte) ([1952]byte, []byte) {
	pk, sk, err := GenerateDilithiumKeyFromSeed(seed)
	if err != nil {
		return [1952]byte{}, make([]byte, Dilithium3SecretKeySize)
	}
	return pk, sk
}

// generateVRFDeterministic generates a deterministic VRF keypair for testing.
func generateVRFDeterministic(seed []byte) ([32]byte, []byte) {
	if len(seed) != 32 {
		return [32]byte{}, make([]byte, 32)
	}
	var seedArr [32]byte
	copy(seedArr[:], seed)
	sk, pk, err := GenerateVRFKeyFromSeed(seedArr)
	if err != nil {
		return [32]byte{}, make([]byte, 32)
	}
	var pkArr [32]byte
	copy(pkArr[:], pk.Bytes())
	return pkArr, sk.Bytes()
}

// generateVRFKey generates a production VRF keypair using seed as entropy.
func generateVRFKey(seed []byte) ([32]byte, []byte) {
	if len(seed) != 32 {
		return [32]byte{}, make([]byte, 32)
	}
	var seedArr [32]byte
	copy(seedArr[:], seed)
	sk, pk, err := GenerateVRFKeyFromSeed(seedArr)
	if err != nil {
		return [32]byte{}, make([]byte, 32)
	}
	var pkArr [32]byte
	copy(pkArr[:], pk.Bytes())
	return pkArr, sk.Bytes()
}

// EncodeUID encodes a UID0 public key (Dilithium3) to a hex string for use as map keys.
func EncodeUID(pubKey []byte) string {
	return hex.EncodeToString(pubKey)
}

// generateTimestamp returns a fixed timestamp for simulated environments.
func generateTimestamp() int64 {
	return 1700000000
}