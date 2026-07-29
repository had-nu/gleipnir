// Genesis block and NetworkID computation for 3CP v2.0.
package protocol

import (
	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

// NetworkIDFromGenesis computes the NetworkID as BLAKE3(GenesisBlock).
func NetworkIDFromGenesis(genesisCBOR []byte) [32]byte {
	return identity.Blake3Hash(genesisCBOR)
}

// GenesisBlockConfig contains the configuration for creating a genesis block.
type GenesisBlockConfig struct {
	NetworkName      string
	CreatedAt        int64
	InitialValidators []ValidatorGenesisSpec
	GenesisMandateHash [32]byte // Pre-computed hash of the genesis mandate
}

// ValidatorGenesisSpec specifies an initial validator for genesis.
type ValidatorGenesisSpec struct {
	ValidatorID  [16]byte
	Dilithium3PK [1952]byte // Dilithium3 public key
	VRFPK        [32]byte   // VRF public key
	ContractHash [32]byte   // Optional contract hash
}

// BuildGenesisBlock constructs the genesis block (index 0) from configuration.
// The genesis block has PrevHash = all zeros and contains the genesis mandate hash.
func BuildGenesisBlock(cfg *GenesisBlockConfig, validatorSigs map[string][]byte) *chain.Block {
	// Genesis mandate as ProvenanceEntry
	mandateEntry := chain.ProvenanceEntry{
		Hash:      cfg.GenesisMandateHash,
		Submitter: [16]byte{}, // Authority = zeros for genesis
		Timestamp: cfg.CreatedAt,
		Label:     "3cp:mandate:v1",
		Signature: nil, // No signature for genesis mandate (authority is zeros)
	}

	block := &chain.Block{
		Index:       0,
		PrevHash:    make([]byte, 32), // All zeros for genesis
		StateRoot:   make([]byte, 32), // Will be set by engine on init
		Proposer:    cfg.InitialValidators[0].ValidatorID,
		Anchored:    []chain.ProvenanceEntry{mandateEntry},
		Lambda1:     0,
		Timestamp:   cfg.CreatedAt,
		Quorum:      chain.QuorumConfig{TotalValidators: len(cfg.InitialValidators), RequiredSigs: len(cfg.InitialValidators)},
		Validators:  make([]chain.ValidatorInfo, 0, len(cfg.InitialValidators)),
		ProtocolVersion: 2,
	}

	// Add validator public keys
	for _, v := range cfg.InitialValidators {
		block.Validators = append(block.Validators, chain.ValidatorInfo{
			ValidatorID:  v.ValidatorID,
			Dilithium3PK: v.Dilithium3PK,
			VRFPK:        v.VRFPK,
			ContractHash: v.ContractHash,
		})
	}

	// Add signatures from all initial validators to PrepareSigs
	for _, v := range cfg.InitialValidators {
		uidHex := identity.EncodeUID(v.Dilithium3PK[:])
		if sig, ok := validatorSigs[uidHex]; ok {
			block.PrepareSigs = append(block.PrepareSigs, sig)
		}
	}

	// Compute block hash
	block.BlockHash = chain.ComputeBlockHash(block)

	return block
}