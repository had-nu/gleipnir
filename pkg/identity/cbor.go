package identity

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// deterministicMode ensures consistent CBOR encoding (canonical).
var deterministicMode cbor.EncMode

func init() {
	var err error
	deterministicMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize CBOR canonical mode: %v", err))
	}
}

// CalculateFinalDigest computes the BLAKE3 digest of all fields (0..13)
func (u *UIDZeroSoulbound) CalculateFinalDigest() ([]byte, error) {
	// Temporarily remove FinalDigest to exclude it from the hash
	origDigest := u.FinalDigest
	u.FinalDigest = nil

	data, err := deterministicMode.Marshal(u)

	// Restore it
	u.FinalDigest = origDigest

	if err != nil {
		return nil, err
	}

	return Hash(data), nil
}

// Seal computes and sets the FinalDigest of the token.
func (u *UIDZeroSoulbound) Seal() error {
	digest, err := u.CalculateFinalDigest()
	if err != nil {
		return err
	}
	u.FinalDigest = digest
	return nil
}

// SerializeCBOR returns the deterministically encoded token byte slice.
func (u *UIDZeroSoulbound) SerializeCBOR() ([]byte, error) {
	return deterministicMode.Marshal(u)
}

// UnmarshalCBOR decodes the bytes into a token.
func UnmarshalCBOR(data []byte) (*UIDZeroSoulbound, error) {
	var uid0 UIDZeroSoulbound
	if err := cbor.Unmarshal(data, &uid0); err != nil {
		return nil, err
	}
	return &uid0, nil
}
