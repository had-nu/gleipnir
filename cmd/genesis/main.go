// Genesis block generator for 3CP v2.0.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/protocol"
	"github.com/had-nu/gleipnir/pkg/smt"
	"github.com/had-nu/gleipnir/pkg/state"
	"gopkg.in/yaml.v3"
)

// GenesisSpec defines the input specification for genesis block creation.
type GenesisSpec struct {
	NetworkName string          `yaml:"network_name"`
	CreatedAt   int64           `yaml:"created_at"`
	Validators  []ValidatorSpec `yaml:"validators"`
	Mandate     MandateSpec     `yaml:"mandate"`
	LegacyAnchor string         `yaml:"legacy_anchor"` // hex-encoded H(B_final) from v1
}

// ValidatorSpec defines a validator in the genesis configuration.
type ValidatorSpec struct {
	UID0PubKey   string `yaml:"uid0_pubkey"`    // hex-encoded Dilithium3 public key
	VRFPubKey    string `yaml:"vrf_pubkey"`     // hex-encoded VRF public key
	ContractHash string `yaml:"contract_hash"`  // hex-encoded contract hash (optional)
}

// MandateSpec defines the genesis mandate configuration.
type MandateSpec struct {
	Label string            `yaml:"label"`
	Rules []MandateRuleSpec `yaml:"rules"`
}

// MandateRuleSpec defines a single rule in the genesis mandate.
type MandateRuleSpec struct {
	EventClass string                 `yaml:"event_class"`
	Fields     map[string]interface{} `yaml:"fields"`
}

// ConsensusConfig holds consensus parameters from the genesis mandate.
type ConsensusConfig struct {
	GraceCycles         uint64 `yaml:"GraceCycles"`
	MinValidators       uint64 `yaml:"MinValidators"`
	BaseIntervalMs      uint64 `yaml:"BaseIntervalMs"`
	MaxCycleDurationMs  uint64 `yaml:"MaxCycleDurationMs"`
	LambdaInterval      uint64 `yaml:"LambdaInterval"`
	MinLambda1          float64 `yaml:"MinLambda1"`
	KeyRotationLeadTime uint64 `yaml:"KeyRotationLeadTime"`
	MinKeyOverlap       uint64 `yaml:"MinKeyOverlap"`
	MaxPendingTTL       uint64 `yaml:"MaxPendingTTL"`
	BatchVerifyWorkers  int    `yaml:"BatchVerifyWorkers"`
}

func main() {
	specPath := flag.String("spec", "", "Path to genesis.yaml specification")
	outputPath := flag.String("output", "genesis.cbor", "Output path for genesis block CBOR")
	signers := flag.String("signers", "", "Comma-separated list of validator private key files")
	importSnapshot := flag.String("import-snapshot", "", "Path to v1.0 snapshot CBOR for migration")
	networkName := flag.String("network-name", "", "Override network name from spec")
	createdAt := flag.Int64("created-at", 0, "Override creation timestamp (Unix seconds)")
	flag.Parse()

	if *specPath == "" && *importSnapshot == "" {
		fmt.Fprintln(os.Stderr, "Error: either --spec or --import-snapshot is required")
		flag.Usage()
		os.Exit(1)
	}

	var spec *GenesisSpec
	var err error

	if *importSnapshot != "" {
		spec, err = importV1Snapshot(*importSnapshot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to import v1 snapshot: %v\n", err)
			os.Exit(1)
		}
	} else {
		spec, err = loadSpec(*specPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load spec: %v\n", err)
			os.Exit(1)
		}
	}

	// Apply overrides
	if *networkName != "" {
		spec.NetworkName = *networkName
	}
	if *createdAt != 0 {
		spec.CreatedAt = *createdAt
	}

	// Validate spec
	if err := spec.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid genesis spec: %v\n", err)
		os.Exit(1)
	}

	// Extract consensus config
	consensusCfg, err := spec.ExtractConsensusConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to extract consensus config: %v\n", err)
		os.Exit(1)
	}

	// Build genesis block
	block, err := BuildGenesisBlock(spec, consensusCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build genesis block: %v\n", err)
		os.Exit(1)
	}

	// Sign if signers provided
	if *signers != "" {
		fmt.Fprintln(os.Stderr, "Warning: signing not fully implemented. Genesis will be unsigned.")
	}

	// Write output
	cborData, err := chain.MarshalCBOR(block)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal genesis block: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputPath, cborData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write output: %v\n", err)
		os.Exit(1)
	}

	// Compute NetworkID
	networkID := protocol.NetworkIDFromGenesis(cborData)

	fmt.Printf("Genesis block written to: %s\n", *outputPath)
	fmt.Printf("NetworkID: %s\n", networkID)
	fmt.Printf("ProtocolVersion: %d\n", protocol.ProtocolVersion)
	fmt.Printf("Validators: %d\n", len(spec.Validators))
	fmt.Printf("Quorum (ceil(2N/3)): %d\n", quorumRequired(len(spec.Validators)))
}

// loadSpec loads and parses the genesis specification from a YAML file.
func loadSpec(path string) (*GenesisSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}

	var spec GenesisSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse genesis spec: %w", err)
	}

	return &spec, nil
}

// Validate checks the genesis specification for correctness.
func (s *GenesisSpec) Validate() error {
	if s.NetworkName == "" {
		return fmt.Errorf("network_name is required")
	}
	if s.CreatedAt <= 0 {
		return fmt.Errorf("created_at must be > 0")
	}
	if len(s.Validators) == 0 {
		return fmt.Errorf("at least one validator is required")
	}

	// Check minimum validators from mandate
	minValidators := s.Mandate.GetMinValidators()
	if uint64(len(s.Validators)) < minValidators {
		return fmt.Errorf("validator count (%d) < MinValidators (%d)", len(s.Validators), minValidators)
	}

	// Validate each validator
	for i, v := range s.Validators {
		if v.UID0PubKey == "" {
			return fmt.Errorf("validator %d: uid0_pubkey is required", i)
		}
		if _, err := hex.DecodeString(v.UID0PubKey); err != nil {
			return fmt.Errorf("validator %d: invalid uid0_pubkey: %w", i, err)
		}
		if v.VRFPubKey == "" {
			return fmt.Errorf("validator %d: vrf_pubkey is required", i)
		}
		if _, err := hex.DecodeString(v.VRFPubKey); err != nil {
			return fmt.Errorf("validator %d: invalid vrf_pubkey: %w", i, err)
		}
	}

	// Validate mandate
	if s.Mandate.Label != "3cp:mandate:v1" {
		return fmt.Errorf("mandate label must be '3cp:mandate:v1'")
	}
	if len(s.Mandate.Rules) == 0 {
		return fmt.Errorf("mandate must have at least one rule")
	}

	return nil
}

// GetMinValidators extracts MinValidators from the genesis mandate.
func (m *MandateSpec) GetMinValidators() uint64 {
	for _, rule := range m.Rules {
		if rule.EventClass == "3cp:consensus-config" {
			if v, ok := rule.Fields["MinValidators"].(float64); ok {
				return uint64(v)
			}
		}
	}
	return 4 // Default
}

// ExtractConsensusConfig extracts consensus parameters from the mandate.
func (s *GenesisSpec) ExtractConsensusConfig() (*ConsensusConfig, error) {
	cfg := &ConsensusConfig{
		GraceCycles:        10,
		MinValidators:      4,
		BaseIntervalMs:     3000,
		MaxCycleDurationMs: 10000,
		LambdaInterval:     10,
		MinLambda1:         0.01,
		KeyRotationLeadTime: 10,
		MinKeyOverlap:      10,
		MaxPendingTTL:      100,
		BatchVerifyWorkers: 0, // auto
	}

	for _, rule := range s.Mandate.Rules {
		if rule.EventClass == "3cp:consensus-config" {
			if v, ok := rule.Fields["GraceCycles"].(float64); ok {
				cfg.GraceCycles = uint64(v)
			}
			if v, ok := rule.Fields["MinValidators"].(float64); ok {
				cfg.MinValidators = uint64(v)
			}
			if v, ok := rule.Fields["BaseIntervalMs"].(float64); ok {
				cfg.BaseIntervalMs = uint64(v)
			}
			if v, ok := rule.Fields["MaxCycleDurationMs"].(float64); ok {
				cfg.MaxCycleDurationMs = uint64(v)
			}
			if v, ok := rule.Fields["LambdaInterval"].(float64); ok {
				cfg.LambdaInterval = uint64(v)
			}
			if v, ok := rule.Fields["MinLambda1"].(float64); ok {
				cfg.MinLambda1 = v
			}
			if v, ok := rule.Fields["KeyRotationLeadTime"].(float64); ok {
				cfg.KeyRotationLeadTime = uint64(v)
			}
			if v, ok := rule.Fields["MinKeyOverlap"].(float64); ok {
				cfg.MinKeyOverlap = uint64(v)
			}
			if v, ok := rule.Fields["MaxPendingTTL"].(float64); ok {
				cfg.MaxPendingTTL = uint64(v)
			}
			if v, ok := rule.Fields["BatchVerifyWorkers"].(float64); ok {
				cfg.BatchVerifyWorkers = int(v)
			}
		}
	}

	return cfg, nil
}

// quorumRequired computes the required quorum: ceil(2N/3).
func quorumRequired(n int) int {
	return (2*n + 2) / 3
}

// BuildGenesisBlock constructs the genesis block from the specification.
func BuildGenesisBlock(spec *GenesisSpec, consensusCfg *ConsensusConfig) (*chain.Block, error) {
	// Create SMT with default depth
	smtTree := smt.New(state.DefaultConfig.SMTDepth)
	smtTree.Root() // initialize

	// Proposer for genesis is the first validator (deterministic)
	var proposer [16]byte
	if len(spec.Validators) > 0 {
		pk, err := hexDecode(spec.Validators[0].UID0PubKey)
		if err != nil {
			return nil, fmt.Errorf("invalid first validator pubkey: %w", err)
		}
		copy(proposer[:], pk[:16])
	}

	// Build validator list
	validators := make([]chain.ValidatorInfo, len(spec.Validators))
	for i, v := range spec.Validators {
		pubKey, err := hexDecode(v.UID0PubKey)
		if err != nil {
			return nil, fmt.Errorf("validator %d: invalid uid0_pubkey: %w", i, err)
		}
		var pk [1952]byte
		copy(pk[:], pubKey)

		vrfPubKey, err := hexDecode(v.VRFPubKey)
		if err != nil {
			return nil, fmt.Errorf("validator %d: invalid vrf_pubkey: %w", i, err)
		}
		var vrfPK [32]byte
		copy(vrfPK[:], vrfPubKey)

		var contractHash [32]byte
		if v.ContractHash != "" {
			ch, err := hexDecode(v.ContractHash)
			if err != nil {
				return nil, fmt.Errorf("validator %d: invalid contract_hash: %w", i, err)
			}
			copy(contractHash[:], ch)
		}

		var validatorID [16]byte
		copy(validatorID[:], pk[:16])

		validators[i] = chain.ValidatorInfo{
			ValidatorID:  validatorID,
			Dilithium3PK: pk,
			VRFPK:        vrfPK,
			ContractHash: contractHash,
		}
	}

	// Build genesis block
	var proposerID [16]byte
	copy(proposerID[:], validators[0].Dilithium3PK[:16])

	block := &chain.Block{
		Index:       0,
		PrevHash:    make([]byte, 32), // All zeros for genesis
		StateRoot:   make([]byte, 32), // Will be set by engine on init
		Proposer:    proposerID,
		Anchored:    []chain.ProvenanceEntry{},
		Lambda1:     0, // No network yet
		Timestamp:   spec.CreatedAt * 1e9, // Convert to nanoseconds
		Quorum: chain.QuorumConfig{
			TotalValidators: len(spec.Validators),
			RequiredSigs:    quorumRequired(len(spec.Validators)),
		},
		Validators:      validators,
		PrepareSigs:     make([][]byte, 0, len(spec.Validators)),
		ProtocolVersion: 2,
	}

	// Add legacy anchor if provided (for v1 migration)
	if spec.LegacyAnchor != "" {
		legacyBytes, err := hexDecode(spec.LegacyAnchor)
		if err != nil {
			return nil, fmt.Errorf("invalid legacy anchor: %w", err)
		}
		block.LegacyAnchor = legacyBytes
	}

	// Compute initial block hash (without signatures for genesis)
	block.BlockHash = computeBlockHash(block)

	return block, nil
}

// computeBlockHash computes the SHA-256 hash of a block per 3CP spec §3.2.
func computeBlockHash(b *chain.Block) []byte {
	h := sha256.New()

	// Index (LE64)
	var idxBuf [8]byte
	binary.LittleEndian.PutUint64(idxBuf[:], b.Index)
	h.Write(idxBuf[:])

	// PrevHash (32 bytes)
	h.Write(b.PrevHash)

	// StateRoot (32 bytes)
	h.Write(b.StateRoot)

	// Proposer (16 bytes)
	h.Write(b.Proposer[:])

	// Anchored entry hashes
	for _, e := range b.Anchored {
		h.Write(e.Hash[:])
	}

	// Timestamp (LE64)
	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], uint64(b.Timestamp))
	h.Write(tsBuf[:])

	return h.Sum(nil)
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		_, err := fmt.Sscanf(s[i:i+2], "%02x", &b[i/2])
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// V1Snapshot represents the exported state from a v1.0 network.
type V1Snapshot struct {
	BlockHeight   uint64            `json:"block_height"`
	LastBlockHash string            `json:"last_block_hash"`     // hex
	SMRoot        string            `json:"smt_root"`            // hex
	ValidatorSet  []V1Validator     `json:"validator_set"`
	ActiveMandates []V1Mandate      `json:"active_mandates"`
	NetworkState  V1NetworkState    `json:"network_state"`
}

// V1Validator represents a validator in v1.0 format.
type V1Validator struct {
	UID0PubKey   string `json:"uid0_pubkey"`   // hex
	VRFPubKey    string `json:"vrf_pubkey"`    // hex
	ContractHash string `json:"contract_hash"` // hex, optional
}

// ToValidatorSpec converts a V1Validator to ValidatorSpec.
func (v V1Validator) ToValidatorSpec() ValidatorSpec {
	return ValidatorSpec{
		UID0PubKey:   v.UID0PubKey,
		VRFPubKey:    v.VRFPubKey,
		ContractHash: v.ContractHash,
	}
}

// V1Mandate represents a mandate in v1.0 format.
type V1Mandate struct {
	MandateID   string `json:"mandate_id"`   // hex
	Authority   string `json:"authority"`    // hex
	Version     uint64 `json:"version"`
	PrevVersion string `json:"prev_version"` // hex
	ValidFrom   int64  `json:"valid_from"`
	ValidUntil  int64  `json:"valid_until"`
	Rules       []V1Rule `json:"rules"`
}

// V1Rule represents a mandate rule in v1.0 format.
type V1Rule struct {
	EventClass           string   `json:"event_class"`
	Description          string   `json:"description"`
	SeverityMin          float64  `json:"severity_min"`
	SeverityMax          float64  `json:"severity_max"`
	AssetCriticalityMin  uint     `json:"asset_criticality_min"`
	RegulatoryScope      []string `json:"regulatory_scope"`
	Mandatory            bool     `json:"mandatory"`
	RequiredFields       []string `json:"required_fields"`
	MaxDeferralSec       uint64   `json:"max_deferral_sec"`
}

// V1NetworkState represents the network state in v1.0 format.
type V1NetworkState struct {
	Cycle          uint64                `json:"cycle"`
	Lambda1        float64               `json:"lambda1"`
	MinLambda1     float64               `json:"min_lambda1"`
	LambdaInterval uint64                `json:"lambda_interval"`
	DecayRate      float64               `json:"decay_rate"`
	Eta            float64               `json:"eta"`
	Nodes          map[string]V1NodeState `json:"nodes"`
	Edges          []V1Edge              `json:"edges"`
}

// V1NodeState represents a node state in v1.0 format.
type V1NodeState struct {
	UID         string  `json:"uid"`
	Status      float64 `json:"status"`
	Consecutive uint64  `json:"consecutive"`
	JoinCycle   uint64  `json:"join_cycle"`
}

// V1Edge represents a reputation graph edge in v1.0 format.
type V1Edge struct {
	From   string  `json:"from"`
	To     string  `json:"to"`
	Weight float64 `json:"weight"`
}

// importV1Snapshot loads a v1.0 snapshot and converts it to a GenesisSpec.
func importV1Snapshot(path string) (*GenesisSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}

	var snapshot V1Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot JSON: %w", err)
	}

	// Convert validators
	validators := make([]ValidatorSpec, len(snapshot.ValidatorSet))
	for i, v := range snapshot.ValidatorSet {
		validators[i] = v.ToValidatorSpec()
	}

	// Convert mandates to genesis mandate
	mandate := convertMandates(snapshot.ActiveMandates)

	// Build genesis spec
	spec := &GenesisSpec{
		NetworkName:   "3cp-migrated-v2",
		CreatedAt:     time.Now().Unix(),
		Validators:    validators,
		Mandate:       mandate,
		LegacyAnchor:  snapshot.LastBlockHash,
	}

	return spec, nil
}

// convertMandates converts v1.0 mandates to a v2.0 genesis mandate.
func convertMandates(v1Mandates []V1Mandate) MandateSpec {
	// Start with default v2.0 mandate
	mandate := MandateSpec{
		Label: "3cp:mandate:v1",
		Rules: []MandateRuleSpec{
			{
				EventClass: "3cp:consensus-config",
				Fields: map[string]interface{}{
					"GraceCycles":           10,
					"MinValidators":         4,
					"BaseIntervalMs":        3000,
					"MaxCycleDurationMs":    10000,
					"LambdaInterval":        10,
					"MinLambda1":            0.01,
					"KeyRotationLeadTime":   10,
					"MinKeyOverlap":         10,
					"MaxPendingTTL":         100,
					"BatchVerifyWorkers":    0,
				},
			},
			{
				EventClass: "3cp:anchor-config",
				Fields: map[string]interface{}{
					"Mode":                "designated",
					"MinRedundancy":       2,
					"AllowedSchemes":      []string{"ipfs", "file"},
				},
			},
			{
				EventClass: "3cp:protocol-version",
				Fields: map[string]interface{}{
					"MinProtocolVersion": 2,
					"MaxProtocolVersion": 2,
				},
			},
		},
	}

	// Override with v1.0 mandate values if present
	for _, m := range v1Mandates {
		for _, rule := range m.Rules {
			if rule.EventClass == "release_gate" || rule.EventClass == "exception_grant" {
				// These are event-specific mandates; preserve as-is
				mandate.Rules = append(mandate.Rules, MandateRuleSpec{
					EventClass: rule.EventClass,
					Fields: map[string]interface{}{
						"SeverityMin":       rule.SeverityMin,
						"SeverityMax":       rule.SeverityMax,
						"AssetCriticalityMin": rule.AssetCriticalityMin,
						"RegulatoryScope":   rule.RegulatoryScope,
						"Mandatory":         rule.Mandatory,
						"RequiredFields":    rule.RequiredFields,
						"MaxDeferralSec":    rule.MaxDeferralSec,
					},
				})
			}
		}
	}

	return mandate
}