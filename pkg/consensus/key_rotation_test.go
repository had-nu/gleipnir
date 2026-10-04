// Key rotation integration tests — 3CP v2.0 spec §8.
//
// These exercise the engine-side half of the protocol: admitting a rotation,
// accepting it once anchored, and verifying consensus signatures with whichever key
// is authoritative for the signing validator in that cycle.
package consensus

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/state"
	"github.com/had-nu/gleipnir/pkg/validation"
)

// rotationEngine builds a single-node engine whose validator is ready to rotate.
type rotationEngine struct {
	engine *Engine
	node   Node
	newPK  [chain.KeyRotationPublicKeySize]byte
	newSK  []byte
	newVRF [chain.KeyRotationVRFKeySize]byte
}

func newRotationEngine(t *testing.T) *rotationEngine {
	t.Helper()

	var networkID [32]byte
	copy(networkID[:], []byte("key-rotation-network"))
	uid, err := identity.NewUIDZero("key-rotation-node", networkID, true)
	if err != nil {
		t.Fatalf("NewUIDZero: %v", err)
	}

	node := Node{UID: *uid, Addr: "node-1"}
	eng := NewEngine(node, time.Second)

	newPK, newSK, err := identity.GenerateDilithiumKeyFromSeed(rotationSeed(42))
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}
	var newVRF [chain.KeyRotationVRFKeySize]byte
	copy(newVRF[:], rotationSeed(43))

	return &rotationEngine{
		engine: eng,
		node:   node,
		newPK:  newPK,
		newSK:  newSK,
		newVRF: newVRF,
	}
}

// rotation builds a signed rotation from the engine's own key to the new key.
func (re *rotationEngine) rotation(t *testing.T, effective, expiry uint64) *chain.KeyRotationEntry {
	t.Helper()
	entry, err := chain.NewKeyRotationEntry(
		re.node.UID.RootID, re.node.UID.SecretKey,
		re.newPK, re.newVRF, re.newSK,
		effective, expiry, time.Now().UnixNano(),
	)
	if err != nil {
		t.Fatalf("NewKeyRotationEntry: %v", err)
	}
	return entry
}

func rotationSeed(n byte) []byte {
	s := make([]byte, identity.Dilithium3SeedSize)
	for i := range s {
		s[i] = n + byte(i)
	}
	return s
}

// advanceTo sets the engine's cycle. The test drives cycles directly rather than
// waiting on the ticker.
func (re *rotationEngine) advanceTo(t *testing.T, cycle uint64) {
	t.Helper()
	re.engine.mu.Lock()
	re.engine.state.Cycle = cycle
	re.engine.syncKeyRotationStateLocked()
	re.engine.mu.Unlock()
}

// SubmitKeyRotation admits a valid rotation and enqueues it for anchoring.
func TestEngineSubmitKeyRotation(t *testing.T) {
	re := newRotationEngine(t)
	ctx := context.Background()

	before := re.engine.PendingCount()
	entry := re.rotation(t, 20, 40)
	if err := re.engine.SubmitKeyRotation(ctx, entry); err != nil {
		t.Fatalf("SubmitKeyRotation: %v", err)
	}
	if got := re.engine.PendingCount(); got != before+1 {
		t.Fatalf("rotation must be enqueued: pending %d -> %d", before, got)
	}
	if _, ok := re.engine.RotationBody(entry.Hash); !ok {
		t.Fatal("rotation body must be retained for later validation")
	}
}

// SubmitKeyRotation rejects a rotation that breaks the rules and enqueues nothing.
func TestEngineSubmitKeyRotationRejectsInvalid(t *testing.T) {
	re := newRotationEngine(t)
	ctx := context.Background()
	before := re.engine.PendingCount()

	// Cycle 0 + KeyRotationLeadTime(10) = 10, so EffectiveCycle 5 is too early.
	tooEarly := re.rotation(t, 5, 40)
	if err := re.engine.SubmitKeyRotation(ctx, tooEarly); !errors.Is(err, validation.ErrKeyRotationLeadTime) {
		t.Fatalf("want ErrKeyRotationLeadTime, got %v", err)
	}

	// Overlap of 1 cycle is below MinKeyOverlap(10).
	shortOverlap := re.rotation(t, 20, 21)
	if err := re.engine.SubmitKeyRotation(ctx, shortOverlap); !errors.Is(err, validation.ErrKeyRotationOverlap) {
		t.Fatalf("want ErrKeyRotationOverlap, got %v", err)
	}

	if got := re.engine.PendingCount(); got != before {
		t.Fatalf("invalid rotations must not be enqueued: pending %d -> %d", before, got)
	}
}

// A rotation anchored in a block is admitted by the engine and becomes authoritative
// once its EffectiveCycle arrives.
func TestEngineAcceptsAnchoredRotation(t *testing.T) {
	re := newRotationEngine(t)
	ctx := context.Background()

	entry := re.rotation(t, 20, 40)
	if err := re.engine.SubmitKeyRotation(ctx, entry); err != nil {
		t.Fatalf("SubmitKeyRotation: %v", err)
	}

	// Anchor it: RunCycle processes the batch and admits the rotation.
	re.engine.RunCycle()

	if _, ok := re.engine.KeyRotationValidator().LastRotationCycle(re.node.UID.RootID); !ok {
		t.Fatal("anchored rotation must be recorded in the key history")
	}
	if _, ok := re.engine.RotationBody(entry.Hash); !ok {
		t.Fatal("rotation body must still be known")
	}

	// Before EffectiveCycle the old key is the only authoritative one.
	re.advanceTo(t, 19)
	keys, err := re.engine.KeyRotationValidator().GetActivePublicKey(re.node.UID.RootID, 19)
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(keys) != 1 || keys[0] != re.node.UID.PublicKey {
		t.Fatal("cycle 19: only the old key should be active")
	}

	// Inside the overlap window both keys are authoritative.
	re.advanceTo(t, 25)
	keys, err = re.engine.KeyRotationValidator().GetActivePublicKey(re.node.UID.RootID, 25)
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(keys) != 2 || keys[0] != re.node.UID.PublicKey || keys[1] != re.newPK {
		t.Fatal("cycle 25: both keys should be active during overlap")
	}

	// After the window only the new key is authoritative.
	re.advanceTo(t, 41)
	keys, err = re.engine.KeyRotationValidator().GetActivePublicKey(re.node.UID.RootID, 41)
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(keys) != 1 || keys[0] != re.newPK {
		t.Fatal("cycle 41: only the new key should be active")
	}
}

// The property that makes rotation safe: a message signed with either the outgoing or
// the incoming key verifies throughout the overlap window, so a validator can rotate
// without the network having to upgrade in lockstep.
func TestEngineVerifySignatureWithOverlap(t *testing.T) {
	re := newRotationEngine(t)

	entry := re.rotation(t, 20, 40)
	if err := re.engine.KeyRotationValidator().ValidateAndRecord(entry); err != nil {
		t.Fatalf("record rotation: %v", err)
	}

	msg := []byte("PREPARE block hash")
	sigOld := identity.SignDilithium(re.node.UID.SecretKey, msg)
	sigNew := identity.SignDilithium(re.newSK, msg)

	// Before EffectiveCycle: only the old signature verifies.
	if !re.engine.verifySignatureWithOverlap(re.node.UID.RootID, msg, sigOld, 19) {
		t.Fatal("old signature must verify before the rotation takes effect")
	}
	if re.engine.verifySignatureWithOverlap(re.node.UID.RootID, msg, sigNew, 19) {
		t.Fatal("new signature must not verify before the rotation takes effect")
	}

	// During overlap: both verify. This is the no-downtime guarantee.
	for cycle := uint64(20); cycle <= 40; cycle++ {
		if !re.engine.verifySignatureWithOverlap(re.node.UID.RootID, msg, sigOld, cycle) {
			t.Fatalf("cycle %d: old signature must verify during overlap", cycle)
		}
		if !re.engine.verifySignatureWithOverlap(re.node.UID.RootID, msg, sigNew, cycle) {
			t.Fatalf("cycle %d: new signature must verify during overlap", cycle)
		}
	}

	// After overlap: only the new signature verifies.
	if re.engine.verifySignatureWithOverlap(re.node.UID.RootID, msg, sigOld, 41) {
		t.Fatal("old signature must stop verifying once the overlap closes")
	}
	if !re.engine.verifySignatureWithOverlap(re.node.UID.RootID, msg, sigNew, 41) {
		t.Fatal("new signature must verify once the rotation is complete")
	}

	// A tampered message never verifies, regardless of key.
	if re.engine.verifySignatureWithOverlap(re.node.UID.RootID, []byte("tampered"), sigNew, 30) {
		t.Fatal("signature over a different message must not verify")
	}

	// An unknown validator has no active keys, so nothing verifies.
	var stranger [16]byte
	copy(stranger[:], []byte("stranger"))
	if re.engine.verifySignatureWithOverlap(stranger, msg, sigNew, 30) {
		t.Fatal("unknown validator must not verify")
	}
}

// A rotation submitted but not yet anchored must not influence signature
// verification: only anchored rotations are authoritative.
func TestEngineUnanchoredRotationIsNotAuthoritative(t *testing.T) {
	re := newRotationEngine(t)

	// Record the body (as if received from a peer) but do not anchor it.
	entry := re.rotation(t, 20, 40)
	if err := re.engine.RecordRotationBody(entry); err != nil {
		t.Fatalf("RecordRotationBody: %v", err)
	}
	if _, ok := re.engine.KeyRotationValidator().LastRotationCycle(re.node.UID.RootID); ok {
		t.Fatal("rotation must not be authoritative before it is anchored")
	}

	msg := []byte("PREPARE block hash")
	sigNew := identity.SignDilithium(re.newSK, msg)
	if re.engine.verifySignatureWithOverlap(re.node.UID.RootID, msg, sigNew, 30) {
		t.Fatal("an unanchored rotation must not make the new key authoritative")
	}
}

// A malformed rotation anchored in a block is skipped without aborting the cycle.
func TestEngineInvalidAnchoredRotationDoesNotStallChain(t *testing.T) {
	re := newRotationEngine(t)

	// Anchor a rotation entry whose body was never registered: the engine cannot
	// validate it, so it must ignore it and carry on.
	re.engine.mu.Lock()
	re.engine.pending = append(re.engine.pending, chain.ProvenanceEntry{
		Hash:      [32]byte{0xAB},
		Submitter: re.node.UID.RootID,
		Timestamp: time.Now().UnixNano(),
		Label:     chain.KeyRotationLabel,
	})
	re.engine.mu.Unlock()

	before := re.engine.BlockCount()
	re.engine.RunCycle()

	if _, ok := re.engine.KeyRotationValidator().LastRotationCycle(re.node.UID.RootID); ok {
		t.Fatal("an unverifiable rotation must not be recorded")
	}
	if got := re.engine.BlockCount(); got != before+1 {
		t.Fatalf("cycle must still commit a block: height %d -> %d", before, got)
	}
}

// RecordRotationBody refuses a body whose hash does not commit to its contents.
func TestEngineRecordRotationBodyRejectsTamperedBody(t *testing.T) {
	re := newRotationEngine(t)

	entry := re.rotation(t, 20, 40)
	entry.EffectiveCycle = 999
	if err := re.engine.RecordRotationBody(entry); !errors.Is(err, chain.ErrHashMismatch) {
		t.Fatalf("want chain.ErrHashMismatch, got %v", err)
	}
}

// Blocks reference the key rotation epoch in force (spec §8, KeyRotationEpoch).
func TestEngineKeyRotationEpochInBlock(t *testing.T) {
	re := newRotationEngine(t)

	// No rotation in force yet.
	re.advanceTo(t, 10)
	re.engine.mu.Lock()
	epoch := re.engine.keyRotationEpochLocked()
	re.engine.mu.Unlock()
	if epoch != 0 {
		t.Fatalf("want epoch 0 before any rotation, got %d", epoch)
	}

	entry := re.rotation(t, 20, 40)
	if err := re.engine.KeyRotationValidator().ValidateAndRecord(entry); err != nil {
		t.Fatalf("record rotation: %v", err)
	}

	// Not yet effective.
	re.advanceTo(t, 19)
	re.engine.mu.Lock()
	epoch = re.engine.keyRotationEpochLocked()
	re.engine.mu.Unlock()
	if epoch != 0 {
		t.Fatalf("want epoch 0 before EffectiveCycle, got %d", epoch)
	}

	// In force.
	re.advanceTo(t, 25)
	re.engine.mu.Lock()
	epoch = re.engine.keyRotationEpochLocked()
	re.engine.mu.Unlock()
	if epoch != 20 {
		t.Fatalf("want epoch 20 while the rotation is in force, got %d", epoch)
	}
}

// The key rotation validator is read from the consensus path (overlap-aware signature
// verification) while RunCycle mutates it from the cycle path. The validator owns its
// own lock precisely so those two can run concurrently without deadlocking on the
// engine mutex, which RunCycle already holds. Run under -race.
func TestEngineKeyRotationConcurrentAccess(t *testing.T) {
	re := newRotationEngine(t)
	v := re.engine.KeyRotationValidator()

	entry := re.rotation(t, 20, 40)
	if err := v.ValidateAndRecord(entry); err != nil {
		t.Fatalf("record rotation: %v", err)
	}

	msg := []byte("PREPARE block hash")
	sigOld := identity.SignDilithium(re.node.UID.SecretKey, msg)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers: overlap-aware verification and active-key lookups, exactly as the
	// PREPARE and COMMIT phases do.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(cycle uint64) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				re.engine.verifySignatureWithOverlap(re.node.UID.RootID, msg, sigOld, cycle)
				if _, err := v.GetActivePublicKey(re.node.UID.RootID, cycle); err != nil {
					t.Errorf("GetActivePublicKey: %v", err)
					return
				}
			}
		}(uint64(19 + i*10))
	}

	// Writer: the cycle path, which holds the engine lock while touching the validator.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for cycle := uint64(0); cycle < 30; cycle++ {
			re.engine.mu.Lock()
			re.engine.state.Cycle = cycle
			re.engine.syncKeyRotationStateLocked()
			re.engine.processKeyRotationEntriesLocked([]chain.ProvenanceEntry{{
				Hash:      entry.Hash,
				Submitter: entry.Submitter,
				Label:     chain.KeyRotationLabel,
			}})
			re.engine.mu.Unlock()
		}
		close(stop)
	}()

	wg.Wait()
}

// The validator's snapshot of the validator set tracks the engine, including for
// multi-node engines created via NewEngineWithPeers.
func TestEngineKeyRotationTracksValidatorSet(t *testing.T) {
	peers := []Peer{testPeer("kr-a"), testPeer("kr-b"), testPeer("kr-c")}
	eng := NewEngineWithPeers(Node{UID: peers[0].UID, Addr: "kr-a"}, time.Second, nil, peers)

	for _, p := range peers {
		keys, err := eng.KeyRotationValidator().GetActivePublicKey(p.UID.RootID, 0)
		if err != nil {
			t.Fatalf("peer %s must be known to the key rotation validator: %v", p.Addr, err)
		}
		if len(keys) != 1 || keys[0] != p.UID.PublicKey {
			t.Fatalf("peer %s: want its registered key as the active key", p.Addr)
		}
	}

	// The validator set the validator holds must match the engine's.
	if got := len(eng.state.ValidatorSet); got != len(peers) {
		t.Fatalf("engine validator set size %d, want %d", got, len(peers))
	}
}

// The key rotation configuration comes from the engine's consensus config.
func TestEngineKeyRotationUsesConfiguredPolicy(t *testing.T) {
	re := newRotationEngine(t)
	v := re.engine.KeyRotationValidator()

	cfg := state.DefaultConfig
	if v.CurrentCycle() != re.engine.Cycle() {
		t.Fatalf("validator cycle %d != engine cycle %d", v.CurrentCycle(), re.engine.Cycle())
	}

	// EffectiveCycle exactly at the lead-time boundary is accepted.
	boundary := re.node.UID.RootID
	atBoundary := re.rotation(t, cfg.KeyRotationLeadTime, cfg.KeyRotationLeadTime+cfg.MinKeyOverlap)
	if err := v.Validate(atBoundary); err != nil {
		t.Fatalf("rotation at the lead-time boundary must validate: %v", err)
	}
	if atBoundary.Submitter != boundary {
		t.Fatal("rotation must be attributed to the engine's validator")
	}
}
