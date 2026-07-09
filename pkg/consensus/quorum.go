package consensus

import (
	"errors"

	"github.com/had-nu/prana-provenance-chain/pkg/identity"
)

var ErrQuorumNotMet = errors.New("quorum: 3/3 signatures required")

func VerifyQuorum(blockHash []byte, sigs [3][]byte, pubKeys [3][]byte) error {
	for i := 0; i < 3; i++ {
		if !identity.VerifyDilithium(pubKeys[i], blockHash, sigs[i]) {
			return ErrQuorumNotMet
		}
	}
	return nil
}
