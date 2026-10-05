// Package lightclient implements the third-party verification protocol of 3CP v2.0
// §12.2: read operations a light client needs, and verification that does not require
// executing consensus.
//
// The verification side is the point of this package. A full node checks its own blocks
// against state it already trusts, so it cannot tell whether that state was earned. A
// light client keeps no state and trusts no operator; it replays nothing and re-derives
// nothing, and checks four things about each block: that its hash is what §5.4 says it
// should be, that enough distinct validators signed it, that the proposer's own
// signature covers the block hash, and that it chains onto the last block already
// verified.
package lightclient

import (
	"context"
	"errors"
	"fmt"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/state"
	"github.com/had-nu/gleipnir/pkg/validation"
)

// Errors returned by verification. They are distinct so a caller can tell a block that
// is malformed apart from one that is well-formed but not authorised, which is the
// difference between "this node is broken" and "this chain is under attack".
var (
	// ErrBlockNotFound means the source has no block at that index.
	ErrBlockNotFound = errors.New("3cp: block not found")

	// ErrNoValidatorSet means verification was attempted without a trusted set. It is
	// deliberately not satisfiable from the block under verification.
	ErrNoValidatorSet = errors.New("3cp: no trusted validator set")

	// ErrValidatorSetMismatch means a block declares a different validator set from the
	// one the caller trusts.
	ErrValidatorSetMismatch = errors.New("3cp: block declares an unexpected validator set")

	// ErrChainBreak means a block does not chain onto the previously verified one.
	ErrChainBreak = errors.New("3cp: block does not chain onto the trusted anchor")

	// ErrBlockHashMismatch means the block's own hash does not match its contents.
	ErrBlockHashMismatch = errors.New("3cp: block hash does not match its contents")

	// ErrQuorumNotMet means too few distinct validators signed the block.
	ErrQuorumNotMet = errors.New("3cp: prepare quorum not met")

	// ErrBadSignature means a signature did not verify against the validator it claims
	// to come from.
	ErrBadSignature = errors.New("3cp: signature does not verify")

	// ErrUnknownProposer means the block was proposed by someone outside the trusted set.
	ErrUnknownProposer = errors.New("3cp: block proposer is not a trusted validator")

	// ErrBitmapMismatch means PrepareSigsBitmap and PrepareSigsPayload disagree.
	ErrBitmapMismatch = errors.New("3cp: prepare bitmap does not match the signature payload")

	// ErrUnsupportedVersion means the block is not a v2 block.
	ErrUnsupportedVersion = errors.New("3cp: unsupported protocol version")

	// ErrDegradedNotAnnounced means the trusted set is below §6.5's threshold and the block
	// failed to carry the marker that mode requires.
	ErrDegradedNotAnnounced = errors.New("3cp: degraded mode not announced")

	// ErrEntryNotAnchored means a Merkle proof did not place the entry in the block.
	ErrEntryNotAnchored = errors.New("3cp: entry is not in the block's state root")
)

// BlockSource is the read side §12.2 requires. *consensus.Engine satisfies it, and so
// does a BoltDB-backed storage reader, which is what lets a light client verify against
// a node it does not control.
type BlockSource interface {
	GetBlock(index uint64) *chain.Block
	BlockCount() uint64
}

// SMTProver produces and checks Sparse Merkle Tree inclusion proofs. The consensus engine
// satisfies it. It is separate from BlockSource so a client can verify against archived
// blocks it has no live node for.
type SMTProver interface {
	ProveSMT(key []byte) ([][32]byte, error)
	VerifySMT(key, value []byte, root [32]byte, proof [][32]byte) bool
}

// TrustAnchor is what a light client believes before it verifies anything: the last
// block it accepted, that block's hash, and the validator set it trusts for the cycles
// covered.
//
// The validator set must come from outside the block being verified -- a genesis block,
// an Anchor Publisher, or a full node the operator has vouched for. It is a parameter
// rather than something the client looks up, because a block that names its own
// validators can be signed entirely by whoever wrote it. Reading the set from the block
// would make every other check in this file decorative.
type TrustAnchor struct {
	// BlockIndex is the index of the last verified block.
	BlockIndex uint64

	// BlockHash is that block's hash, which the next block's PrevHash must equal. A nil
	// BlockHash means nothing has been verified yet, and the anchor accepts exactly one
	// block: index 0, with no predecessor to check. It is not a wildcard.
	BlockHash []byte

	// Validators is the trusted canonical validator set.
	Validators []chain.ValidatorInfo

	// Rotations are the key rotations in force, as a light client learns them from the
	// protocol entries it has already verified. A rotation changes which key a validator
	// signs with, so a client that ignored them would reject every signature from a
	// validator that has rotated.
	Rotations []*chain.KeyRotationEntry
}

// Service implements the §12.2 read operations and block verification.
type Service struct {
	source BlockSource
	prover SMTProver

	// maxStreamBounds how far a single StreamBlocks call will read, so one request
	// cannot ask a node to serialise its entire history.
	maxStreamBlocks uint64
}

// Option configures a Service.
type Option func(*Service)

// WithMaxStreamBlocks caps how many blocks a single StreamBlocks call returns.
func WithMaxStreamBlocks(n uint64) Option {
	return func(s *Service) {
		if n > 0 {
			s.maxStreamBlocks = n
		}
	}
}

// New creates a light client service over a block source.
func New(source BlockSource, prover SMTProver, opts ...Option) *Service {
	s := &Service{source: source, prover: prover, maxStreamBlocks: 4096}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GetBlock returns the block at an index (SPEC §12.2).
func (s *Service) GetBlock(index uint64) (*chain.Block, error) {
	if s.source == nil {
		return nil, fmt.Errorf("%w: no block source configured", ErrBlockNotFound)
	}
	block := s.source.GetBlock(index)
	if block == nil {
		return nil, fmt.Errorf("%w: index %d", ErrBlockNotFound, index)
	}
	return block, nil
}

// GetValidatorSet returns the trusted validator set for a cycle (SPEC §12.2).
//
// The set is not derived from any block. It comes from the source's configured
// validator set, which a client only trusts because it supplied the trust anchor, so
// this cannot be used to launder a block's own claim about who is entitled to sign it.
func (s *Service) GetValidatorSet(validators []chain.ValidatorInfo, cycle uint64) ([]chain.ValidatorInfo, error) {
	if len(validators) == 0 {
		return nil, ErrNoValidatorSet
	}
	out := make([]chain.ValidatorInfo, len(validators))
	copy(out, validators)
	return out, nil
}

// GetMerkleProof returns an SMT inclusion proof for a key at a block index (SPEC §12.2).
//
// The proof is against the tree's current state, not the block's, so a client that wants
// to tie an entry to a specific block must check the proof against that block's
// StateRoot. VerifyAnchored does that.
func (s *Service) GetMerkleProof(key [32]byte) ([][32]byte, error) {
	if s.prover == nil {
		return nil, errors.New("3cp: no SMT prover configured")
	}
	return s.prover.ProveSMT(key[:])
}

// StreamBlocks streams blocks from startIndex (SPEC §12.2), bounded so a single request
// cannot walk the whole history.
func (s *Service) StreamBlocks(ctx context.Context, startIndex uint64) (<-chan *chain.Block, error) {
	if s.source == nil {
		return nil, fmt.Errorf("%w: no block source configured", ErrBlockNotFound)
	}

	out := make(chan *chain.Block, 64)
	go func() {
		defer close(out)
		// maxStreamBlocks counts blocks, so the last index is one below the bound.
		end := startIndex + s.maxStreamBlocks - 1
		if total := s.source.BlockCount(); total > 0 && end >= total {
			end = total - 1
		}
		for i := startIndex; i <= end; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			block := s.source.GetBlock(i)
			if block == nil {
				return
			}
			select {
			case out <- block:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// VerifyBlock checks a block against a trust anchor, without executing consensus
// (SPEC §12.2 and notes/light-client-verification.md).
//
// In order:
//
//  1. The block is a v2 block.
//  2. It chains onto the anchor: exactly the next index, and PrevHash equal to the
//     anchor's hash. A block that skips ahead cannot be verified, because nothing links
//     it to what came before.
//  3. Its declared validator set is the trusted one. A block may not quietly add or drop
//     validators; §7.1 says the set changes only through protocol entries.
//  4. Its own hash matches its contents, per §5.4.
//  5. Its proposer is a trusted validator.
//  6. PrepareSigsBitmap and PrepareSigsPayload agree, and enough distinct validators
//     signed: ceil(2N/3), or 1 when the trusted set is smaller than four (§6.5).
//  7. Every PREPARE signature verifies against a distinct validator, pairing the payload
//     with the bitmap.
//  8. CommitSig verifies against the proposer.
//
// The quorum follows §6.5: a chain with fewer than four validators operates degraded, where
// any single valid signature finalises a block, and every block in it MUST carry
// Metadata["3cp:degraded-block"]. Below that threshold the marker is therefore required,
// not merely tolerated, so a small chain cannot quietly produce blocks that look normal.
//
// What the block's own metadata cannot do is decide which regime applies. That is taken
// from the trusted validator set, and checkValidatorSet has already established that the
// block declares the same identities. A block in a chain of four or more cannot lower its
// own quorum by labelling itself degraded.
func (s *Service) VerifyBlock(block *chain.Block, anchor TrustAnchor) error {
	if block == nil {
		return ErrBlockNotFound
	}
	if block.ProtocolVersion != 2 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, block.ProtocolVersion)
	}
	if len(anchor.Validators) == 0 {
		return ErrNoValidatorSet
	}

	// 2. Chain linkage.
	//
	// A nil anchor hash means the client has verified nothing yet, so only the very first
	// block is acceptable and there is no predecessor to compare against. Treating a nil
	// hash as "skip the check" instead would let any block be taken as the first.
	if anchor.BlockHash == nil {
		if block.Index != 0 {
			return fmt.Errorf("%w: index %d cannot be the first block", ErrChainBreak, block.Index)
		}
	} else {
		if block.Index != anchor.BlockIndex+1 {
			return fmt.Errorf("%w: index %d does not follow the anchor at %d",
				ErrChainBreak, block.Index, anchor.BlockIndex)
		}
		if !bytesEqual(anchor.BlockHash, block.PrevHash) {
			return fmt.Errorf("%w: PrevHash %x does not match the anchor hash %x",
				ErrChainBreak, block.PrevHash, anchor.BlockHash)
		}
	}

	// 3. The declared set must be the trusted one.
	if err := checkValidatorSet(block.Validators, anchor.Validators); err != nil {
		return err
	}

	// 4. Self-consistency. Checked before the signatures, since every signature is over
	// the block hash: verifying signatures against a hash that does not match the block
	// would be checking nothing.
	if computed := chain.ComputeBlockHash(block); !bytesEqual(computed, block.BlockHash) {
		return fmt.Errorf("%w: computed %x, block claims %x", ErrBlockHashMismatch, computed, block.BlockHash)
	}

	// 5. Proposer must be trusted. A block proposed by an identity outside the set could
	// satisfy every other check while being signed entirely by whoever wrote it.
	if indexOf(anchor.Validators, block.Proposer) < 0 {
		return fmt.Errorf("%w: %x", ErrUnknownProposer, block.Proposer)
	}

	// 6. Bitmap and payload must agree, and enough validators must have signed.
	signers, err := bitmapSigners(block)
	if err != nil {
		return err
	}
	degraded := len(anchor.Validators) < DegradedThreshold
	required := requiredQuorum(len(anchor.Validators))

	// §6.5 requires every block of a degraded chain to say so. Enforcing the marker is
	// what keeps a sub-quorum chain from producing blocks indistinguishable from normal
	// ones, which is the whole reason the mode is announced.
	if degraded && !isDegradedBlock(block) {
		return fmt.Errorf("%w: %d validators means degraded mode, which §6.5 requires to be "+
			"announced with %s", ErrDegradedNotAnnounced, len(anchor.Validators), DegradedLabel)
	}
	if len(signers) < required {
		return fmt.Errorf("%w: %d of %d validators signed, %d required",
			ErrQuorumNotMet, len(signers), len(anchor.Validators), required)
	}

	// 7. Every signature, attributed to a distinct validator.
	//
	// The payload is compacted: PrepareSigs holds only the signers' signatures, in
	// ascending validator order, so payload position i belongs to bitmapSigners()[i] and
	// not to validator i. Reading it positionally would attribute signatures to the wrong
	// validators, which rejects honest blocks and, worse, could credit a signature to a
	// validator that never signed.
	//
	// Each signature must additionally be credited to a distinct validator, so one key
	// cannot sign twice and satisfy quorum on its own.
	keys := newKeyResolver(anchor)
	cycleKeys, err := keys.keysForCycle(block.Index)
	if err != nil {
		return err
	}
	credited := make([]bool, len(anchor.Validators))
	distinct := 0
	for i, sig := range block.PrepareSigs {
		// The validator the bitmap says this position belongs to.
		claimed := signers[i]

		// Credit it only if that validator produced the signature. The bitmap is a claim
		// about who signed, not proof, so it is checked rather than trusted.
		verified := false
		for _, pk := range cycleKeys[anchor.Validators[claimed].ValidatorID] {
			if identity.VerifyDilithium(pk[:], block.BlockHash, sig) {
				verified = true
				break
			}
		}
		if !verified {
			return fmt.Errorf("%w: prepare signature %d does not verify for validator %x",
				ErrBadSignature, i, anchor.Validators[claimed].ValidatorID)
		}
		if credited[claimed] {
			return fmt.Errorf("%w: validator %x credited twice",
				ErrQuorumNotMet, anchor.Validators[claimed].ValidatorID)
		}
		credited[claimed] = true
		distinct++
	}
	if distinct < required {
		return fmt.Errorf("%w: %d distinct validators signed, %d required",
			ErrQuorumNotMet, distinct, required)
	}

	// 8. The proposer's own signature over the block hash.
	proposerKeys, ok := cycleKeys[block.Proposer]
	if !ok {
		return fmt.Errorf("%w: %x has no key in this cycle", ErrUnknownProposer, block.Proposer)
	}
	commitOK := false
	for _, pk := range proposerKeys {
		if identity.VerifyDilithium(pk[:], block.BlockHash, block.CommitSig) {
			commitOK = true
			break
		}
	}
	if !commitOK {
		return fmt.Errorf("%w: COMMIT signature from proposer %x", ErrBadSignature, block.Proposer)
	}

	return nil
}

// VerifyAnchored checks that an entry is provably included in a block, using an SMT proof
// (notes/light-client-verification.md).
//
// The proof is taken against the live tree, so the block's own StateRoot is what the
// proof is checked against. That is what makes the check meaningful: a proof against
// today's tree says nothing about a block from last week unless the root is pinned to
// that block.
func (s *Service) VerifyAnchored(block *chain.Block, key [32]byte, proof [][32]byte) error {
	if block == nil {
		return ErrBlockNotFound
	}
	root, err := s.stateRootOf(block)
	if err != nil {
		return err
	}
	if s.prover.VerifySMT(key[:], key[:], root, proof) {
		return nil
	}
	return fmt.Errorf("%w: key %x not in state root %x", ErrEntryNotAnchored, key, root)
}

// stateRootOf returns the block's state root, which is the only root a light client may
// check a proof against.
func (s *Service) stateRootOf(block *chain.Block) ([32]byte, error) {
	var root [32]byte
	if len(block.StateRoot) != 32 {
		return root, fmt.Errorf("%w: state root is %d bytes, want 32",
			ErrBlockHashMismatch, len(block.StateRoot))
	}
	copy(root[:], block.StateRoot)
	return root, nil
}

// keyResolver derives, for a given cycle, which keys each validator may sign with.
//
// It builds on validation.KeyRotationValidator rather than reimplementing overlap
// selection, so the light client and the full nodes agree on which key is authoritative
// in a cycle -- if they disagreed, a rotated validator's blocks would verify for the
// network and fail for every observer.
type keyResolver struct {
	validator *validation.KeyRotationValidator
}

func newKeyResolver(anchor TrustAnchor) *keyResolver {
	info := make([]state.ValidatorInfo, 0, len(anchor.Validators))
	for _, v := range anchor.Validators {
		info = append(info, state.ValidatorInfo{
			ValidatorID:  v.ValidatorID,
			Dilithium3PK: v.Dilithium3PK,
			VRFPK:        v.VRFPK,
			ContractHash: v.ContractHash,
		})
	}
	v := validation.NewKeyRotationValidator(info, anchor.BlockIndex, rotationConfig())
	for _, r := range anchor.Rotations {
		if r == nil {
			continue
		}
		// A rotation the client cannot check against its own trusted set is not one it
		// should honour. Ignoring it is safe: the validator stays on its previous key,
		// which is exactly what a client that has not seen the rotation should assume.
		if err := admitRotation(v, r); err != nil {
			continue
		}
	}
	return &keyResolver{validator: v}
}

// admitRotation checks the parts of §8.2 a verifier can evaluate, and records the
// rotation if they hold.
//
// It deliberately does not use KeyRotationValidator.Validate, which applies all five
// admission rules. Three of them are properties of the rotation itself and are checked
// here:
//
//	rule 1: the outgoing key authorises the rotation
//	rule 2: the incoming key authorises the rotation
//	rule 4: the overlap window is long enough
//
// Rule 3 is not checked, because it cannot be. It requires EffectiveCycle to be at least
// KeyRotationLeadTime cycles after the cycle in which the rotation was *submitted*, and
// a light client reading a historical chain has no way to know when it was submitted --
// only when it took effect. Enforcing it against the block's cycle instead would reject
// perfectly valid rotations whose lead time had already elapsed.
//
// Rule 5, no two rotations effective in the same cycle, is enforced by RecordRotation
// itself.
func admitRotation(v *validation.KeyRotationValidator, r *chain.KeyRotationEntry) error {
	if !r.VerifyHash() {
		return chain.ErrHashMismatch
	}

	// Rule 1: the key authoritative immediately before the rotation must have signed it.
	outgoing, err := v.GetActivePublicKey(r.Submitter, r.EffectiveCycle-1)
	if err != nil || len(outgoing) == 0 {
		return err
	}
	payload, err := r.PayloadBytes()
	if err != nil {
		return err
	}
	oldOK := false
	for _, pk := range outgoing {
		if identity.VerifyDilithium(pk[:], payload, r.SignatureOld) {
			oldOK = true
			break
		}
	}
	if !oldOK {
		return errors.New("3cp: rotation not signed by the outgoing key")
	}

	// Rule 2: the incoming key must sign its own admission.
	if !identity.VerifyDilithium(r.NewPublicKey[:], payload, r.SignatureNew) {
		return errors.New("3cp: rotation not signed by the incoming key")
	}

	// Rule 4: both keys must be authoritative together for long enough.
	if r.ExpiryCycle < r.EffectiveCycle+rotationConfig().MinKeyOverlap {
		return errors.New("3cp: rotation overlap window shorter than the configured minimum")
	}

	return v.RecordRotation(r)
}

// keysForCycle returns the authoritative keys per validator for a cycle.
func (k *keyResolver) keysForCycle(cycle uint64) (map[[16]byte][][chain.KeyRotationPublicKeySize]byte, error) {
	out := make(map[[16]byte][][chain.KeyRotationPublicKeySize]byte)
	for _, id := range k.validator.ValidatorIDs() {
		keys, err := k.validator.GetActivePublicKey(id, cycle)
		if err != nil {
			continue
		}
		out[id] = keys
	}
	return out, nil
}

// checkValidatorSet requires the block to declare exactly the trusted set, by identity.
//
// Keys are allowed to differ from the anchor's, because a rotation legitimately changes
// them; identities are not, because §7.1 makes the set immutable except through protocol
// entries that this verification path does not interpret. Comparing identities only is
// what makes the check meaningful during a rotation.
func checkValidatorSet(declared, trusted []chain.ValidatorInfo) error {
	if len(declared) != len(trusted) {
		return fmt.Errorf("%w: block declares %d validators, %d trusted",
			ErrValidatorSetMismatch, len(declared), len(trusted))
	}
	present := make(map[[16]byte]bool, len(declared))
	for _, v := range declared {
		present[v.ValidatorID] = true
	}
	for _, v := range trusted {
		if !present[v.ValidatorID] {
			return fmt.Errorf("%w: block omits trusted validator %x",
				ErrValidatorSetMismatch, v.ValidatorID)
		}
	}
	return nil
}

// bitmapSigners returns the validator positions marked by the bitmap, ascending, and
// checks the bitmap against the payload.
//
// The payload is compacted, so this pairing is the whole meaning of the two fields: the
// bitmap says who signed, the payload holds their signatures in that order. Without the
// check a block could set enough bits to look like quorum while supplying fewer
// signatures, and the quorum count would pass on data that is never verified.
func bitmapSigners(block *chain.Block) ([]int, error) {
	bitmap := block.PrepareSigsBitmap

	// Bits beyond the validator set name no one, so they cannot be counted.
	// len(anchor.Validators) is not available here; the caller bounds the result.
	signers := make([]int, 0, len(block.PrepareSigs))
	for i := 0; i < len(bitmap)*8; i++ {
		if bitSet(bitmap, i) {
			signers = append(signers, i)
		}
	}

	if len(signers) != len(block.PrepareSigs) {
		return nil, fmt.Errorf("%w: bitmap marks %d signers, payload holds %d",
			ErrBitmapMismatch, len(signers), len(block.PrepareSigs))
	}
	return signers, nil
}

// DegradedLabel is the Metadata key §6.5 requires on every block of a degraded chain.
const DegradedLabel = "3cp:degraded-block"

// DegradedThreshold is the validator count below which §6.5 puts the protocol in degraded
// mode. The spec states it as the literal 4, and state.DefaultConfig's MinValidators
// agrees; it is a constant here so a verifier does not inherit whatever the operator
// happened to configure.
const DegradedThreshold = 4

// isDegradedBlock reports whether a block carries the degraded marker.
func isDegradedBlock(block *chain.Block) bool {
	value, ok := block.Metadata[DegradedLabel]
	return ok && string(value) == "true"
}

// requiredQuorum returns how many distinct signatures a block needs.
//
// It is ceil(2N/3) normally, and 1 below §6.5's threshold, where any single valid
// signature finalises a block.
func requiredQuorum(n int) int {
	if n < DegradedThreshold {
		return 1
	}
	return normalQuorum(n)
}

// normalQuorum returns ceil(2N/3), the threshold of SPEC §12.2.
func normalQuorum(n int) int {
	if n <= 0 {
		return 0
	}
	return (2*n + 2) / 3
}

// bitSet reports whether bit i of a big-endian-indexed bitfield is set.
//
// The bit order follows consensus: validator i occupies bit i/8 of the byte with mask
// 1<<(i%8), least significant bit first within each byte. It has to match the engine's
// layout exactly, or a client would attribute signatures to the wrong validators.
func bitSet(bitmap []byte, i int) bool {
	if i/8 >= len(bitmap) {
		return false
	}
	return bitmap[i/8]&(1<<(i%8)) != 0
}

// indexOf finds a validator's position in the trusted set.
func indexOf(validators []chain.ValidatorInfo, id [16]byte) int {
	for i := range validators {
		if validators[i].ValidatorID == id {
			return i
		}
	}
	return -1
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
