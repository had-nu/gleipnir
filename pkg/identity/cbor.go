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

func (u *UIDZeroSoulbound) CalculateFinalDigest() ([]byte, error) {
	origDigest := u.FinalDigest
	u.FinalDigest = nil

	data, err := deterministicMode.Marshal(u)

	u.FinalDigest = origDigest

	if err != nil {
		return nil, err
	}

	return Hash(data), nil
}

func (u *UIDZeroSoulbound) Seal() error {
	digest, err := u.CalculateFinalDigest()
	if err != nil {
		return err
	}
	u.FinalDigest = digest
	return nil
}

func (u *UIDZeroSoulbound) SerializeCBOR() ([]byte, error) {
	return deterministicMode.Marshal(u)
}

func UnmarshalCBOR(data []byte) (*UIDZeroSoulbound, error) {
	var uid0 UIDZeroSoulbound
	if err := cbor.Unmarshal(data, &uid0); err != nil {
		return nil, err
	}
	return &uid0, nil
}
