// IPC quorum — M-of-N signing with Dilithium3.
package consensus

import (
	"errors"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

var ErrQuorumNotMet = errors.New("IPC quorum: required signatures not met")

// VerifyQuorum verifies that at least RequiredSigs valid signatures exist.
// sigs: slice of signatures (any order)
// pubKeys: slice of validator public keys (any order)
// quorum: quorum configuration (TotalValidators, RequiredSigs)
// Returns error if less than RequiredSigs valid signatures are found.
func VerifyQuorum(blockHash []byte, sigs [][]byte, pubKeys [][]byte, quorum chain.QuorumConfig) error {
	if !quorum.IsValid() {
		return ErrQuorumNotMet
	}

	validCount := 0
	// For each signature, find if it matches any validator's public key
	for _, sig := range sigs {
		if len(sig) == 0 {
			continue
		}
		for _, pk := range pubKeys {
			if len(pk) == 0 {
				continue
			}
			if identity.VerifyDilithium(pk, blockHash, sig) {
				validCount++
				break // This signature is valid, count it and move to next signature
			}
		}
	}

	if validCount < quorum.RequiredSigs {
		return ErrQuorumNotMet
	}
	return nil
}

// VerifyQuorumLegacy is the legacy 3/3 verification (for backward compatibility).
func VerifyQuorumLegacy(blockHash []byte, sigs [3][]byte, pubKeys [3][]byte) error {
	for i := 0; i < 3; i++ {
		if !identity.VerifyDilithium(pubKeys[i], blockHash, sigs[i]) {
			return ErrQuorumNotMet
		}
	}
	return nil
}