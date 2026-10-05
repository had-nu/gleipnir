// IPC identity — CBOR serialization.
package identity

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var deterministicMode cbor.EncMode

func init() {
	var err error
	deterministicMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize CBOR canonical mode: %v", err))
	}
}

// publicView is the subset of UIDZeroSoulbound that FinalDigest commits to.
//
// FinalDigest is the value a third party re-derives in order to check an identity,
// so it has to be computable from public data alone. Marshalling the full struct
// committed to SecretKey and VRFSecretKey, which meant two problems: no verifier
// holding only public fields could recompute the digest, and the digest published
// alongside the identity was itself a commitment to the private keys — enough to
// confirm a guessed entropy string offline.
//
// The CBOR keys are carried over unchanged so the field numbering on the wire is
// unaffected; only the two secret-bearing keys are absent. That absence is what
// makes the digest independent of whether the in-memory copy currently holds its
// secret keys, which the old omitempty-based encoding was not.
type publicView struct {
	RootID       [16]byte   `cbor:"0,keyasint"`
	PublicKey    [1952]byte `cbor:"1,keyasint"`
	VRFPublicKey [32]byte   `cbor:"3,keyasint"`
	ContractHash [32]byte   `cbor:"5,keyasint"`
	FinalDigest  [32]byte   `cbor:"6,keyasint"`
	Simulated    bool       `cbor:"7,keyasint"`
}

func (u *UIDZeroSoulbound) public() publicView {
	return publicView{
		RootID:       u.RootID,
		PublicKey:    u.PublicKey,
		VRFPublicKey: u.VRFPublicKey,
		ContractHash: u.ContractHash,
		Simulated:    u.Simulated,
	}
}

// CalculateFinalDigest returns BLAKE3-256 over the canonical CBOR encoding of the
// identity's public fields with FinalDigest zeroed, making the digest a fixed point
// of Seal.
func (u *UIDZeroSoulbound) CalculateFinalDigest() ([32]byte, error) {
	view := u.public()
	view.FinalDigest = [32]byte{}

	data, err := deterministicMode.Marshal(&view)
	if err != nil {
		return [32]byte{}, err
	}

	return Blake3Hash(data), nil
}

// Seal recomputes and stores FinalDigest.
func (u *UIDZeroSoulbound) Seal() error {
	digest, err := u.CalculateFinalDigest()
	if err != nil {
		return err
	}
	u.FinalDigest = digest
	return nil
}

// VerifyDigest reports whether FinalDigest matches the recomputed digest of the
// public fields.
func (u *UIDZeroSoulbound) VerifyDigest() bool {
	want, err := u.CalculateFinalDigest()
	if err != nil {
		return false
	}
	return want == u.FinalDigest
}

// SerializeCBOR encodes the full identity, secret keys included.
func (u *UIDZeroSoulbound) SerializeCBOR() ([]byte, error) {
	return deterministicMode.Marshal(u)
}

// UnmarshalCBOR decodes a full identity from canonical CBOR.
//
// This restores both secret keys, so callers must treat the result as sensitive
// material and must not accept it from an untrusted source without establishing
// provenance first — a decoded identity carries no proof that its keys are the
// ones the network holds.
func UnmarshalCBOR(data []byte) (*UIDZeroSoulbound, error) {
	var uid0 UIDZeroSoulbound
	if err := cbor.Unmarshal(data, &uid0); err != nil {
		return nil, err
	}
	return &uid0, nil
}
