// Mandate admission and compliance integration tests — 3CP v2.0 spec §13.
//
// The verification core in pkg/validation was written and tested without anything
// calling it. These exercise the engine half: admitting an authentic mandate, refusing
// a forged one, checking submissions against the mandates they claim, and answering the
// auditor's question.
package consensus

import (
	"errors"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/validation"
)

// mandateEngine is a single-node engine whose own key can issue mandates.
type mandateEngine struct {
	engine *Engine
	node   Node
}

func newMandateEngine(t *testing.T) *mandateEngine {
	t.Helper()

	var networkID [32]byte
	copy(networkID[:], []byte("mandate-network"))
	uid, err := identity.NewUIDZero("mandate-node", networkID, true)
	if err != nil {
		t.Fatalf("NewUIDZero: %v", err)
	}
	node := Node{UID: *uid, Addr: "node-1"}
	return &mandateEngine{engine: NewEngine(node, time.Second), node: node}
}

// signedMandate builds a mandate signed by the engine's own validator key, which is the
// node registered in the engine's validator set and therefore resolvable as an
// authority.
func (me *mandateEngine) signedMandate(t *testing.T, mutate func(*chain.MandateEntry)) *chain.MandateEntry {
	t.Helper()

	m := &chain.MandateEntry{
		Authority:  me.node.UID.RootID,
		Version:    1,
		ValidFrom:  time.Now().Add(-time.Hour).UnixNano(),
		ValidUntil: time.Now().Add(time.Hour).UnixNano(),
		Rules: []chain.Rule{{
			EventClass:     "3cp:consensus-config",
			RequiredFields: []string{"Signature", "Reference"},
			Mandatory:      true,
		}},
	}
	if mutate != nil {
		mutate(m)
	}
	if err := m.SignWithAuthority(me.node.UID.SecretKey); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}
	return m
}

// TestEngineSubmitMandateAdmitsAuthentic is the happy path: a mandate signed by a
// registered key becomes findable by the resolver and retained as a body.
func TestEngineSubmitMandateAdmitsAuthentic(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)

	if err := me.engine.SubmitMandate(mandate); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}

	got, ok := me.engine.MandateBody(mandate.ID)
	if !ok {
		t.Fatal("the admitted mandate has no retained body")
	}
	if got.ID != mandate.ID {
		t.Error("retained body has the wrong identifier")
	}
	if _, found := me.engine.MandateResolver().GetMandateByID(mandate.ID); !found {
		t.Error("the admitted mandate is not in the resolver, so no submission can be checked against it")
	}

	active, err := me.engine.ActiveMandates(0)
	if err != nil {
		t.Fatalf("ActiveMandates: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("got %d active mandates, want 1", len(active))
	}
}

// TestEngineSubmitMandateRejectsUnsigned is the end-to-end security property.
//
// Nothing verified mandate.cddl's Signature at key 10, so exposing a way to install one
// without checking it would have created unauthenticated policy injection: a caller could
// have named any RootID as the issuer and had the resulting rules enforced on every
// submission that referenced them.
func TestEngineSubmitMandateRejectsUnsigned(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)

	mandate.Signature = nil
	mandate.ID = mandate.MandateID()

	err := me.engine.SubmitMandate(mandate)
	if err == nil {
		t.Fatal("an unsigned mandate was admitted as enforceable policy")
	}
	if !errors.Is(err, chain.ErrMandateSignature) {
		t.Errorf("got %v, want it to wrap chain.ErrMandateSignature", err)
	}
	if _, ok := me.engine.MandateResolver().GetMandateByID(mandate.ID); ok {
		t.Error("the rejected mandate still reached the resolver")
	}
}

// TestEngineSubmitMandateRejectsForeignSigner signs the mandate with a key the chain has
// never seen while naming a registered RootID as the authority.
func TestEngineSubmitMandateRejectsForeignSigner(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)

	_, attackerSK, err := identity.GenerateDilithiumKeyFromSeed(rotationSeed(77))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := mandate.SignWithAuthority(attackerSK); err != nil {
		t.Fatalf("re-sign as attacker: %v", err)
	}

	if err := me.engine.SubmitMandate(mandate); err == nil {
		t.Fatal("a mandate signed by an unregistered key was admitted")
	}
}

// TestEngineSubmitMandateEnqueuesForAnchoring checks the mandate is anchored like any
// other provenance entry, labelled so peers can recognise it.
func TestEngineSubmitMandateEnqueuesForAnchoring(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)

	if err := me.engine.SubmitMandate(mandate); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}

	me.engine.mu.Lock()
	pending := append([]chain.ProvenanceEntry(nil), me.engine.pending...)
	me.engine.mu.Unlock()

	if len(pending) != 1 {
		t.Fatalf("got %d pending entries, want 1", len(pending))
	}
	if pending[0].Label != chain.MandateLabel {
		t.Errorf("label is %q, want %q", pending[0].Label, chain.MandateLabel)
	}
	if pending[0].Hash != mandate.ID {
		t.Error("the anchored entry does not carry the mandate identifier as its hash")
	}
}

// TestEngineEnqueueEnforcesMandateClaim is submission-time enforcement: an entry that
// asserts it satisfies a mandate must actually carry the fields that mandate requires.
func TestEngineEnqueueEnforcesMandateClaim(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)
	if err := me.engine.SubmitMandate(mandate); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}
	// SubmitMandate's own entry references the mandate; drain it so the assertions below
	// are about entries we construct.
	me.engine.mu.Lock()
	me.engine.pending = nil
	me.engine.mu.Unlock()

	base := chain.ProvenanceEntry{
		Hash:       [32]byte{0xAA},
		Submitter:  [16]byte{0xBB},
		Timestamp:  time.Now().UnixNano(),
		Label:      "3cp:consensus-config",
		MandateRef: &mandate.ID,
	}

	// Missing both required fields.
	if err := me.engine.Enqueue(base); err == nil {
		t.Fatal("an entry claiming a mandate without its required fields was accepted")
	} else if !errors.Is(err, validation.ErrMandateMissingRequiredField) {
		t.Errorf("got %v, want it to wrap ErrMandateMissingRequiredField", err)
	}

	// Signature present, Reference still missing.
	partial := base
	partial.Hash = [32]byte{0xAC}
	partial.Signature = []byte{0x01}
	if err := me.engine.Enqueue(partial); err == nil {
		t.Fatal("an entry missing only the Reference field was accepted")
	}

	// Both present.
	complete := partial
	complete.Hash = [32]byte{0xAD}
	ref := [32]byte{0xEE}
	complete.Reference = &ref
	if err := me.engine.Enqueue(complete); err != nil {
		t.Fatalf("a fully compliant entry was rejected: %v", err)
	}
}

// TestEngineEnqueueIgnoresUnreferencedEntries checks that the mandate mechanism does not
// swallow ordinary traffic. Most entries in a provenance chain are governed by nothing.
func TestEngineEnqueueIgnoresUnreferencedEntries(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)
	if err := me.engine.SubmitMandate(mandate); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}
	me.engine.mu.Lock()
	me.engine.pending = nil
	me.engine.mu.Unlock()

	plain := chain.ProvenanceEntry{
		Hash:      [32]byte{0x11},
		Submitter: [16]byte{0x22},
		Timestamp: time.Now().UnixNano(),
		Label:     "some-other-event",
	}
	if err := me.engine.Enqueue(plain); err != nil {
		t.Fatalf("an entry governed by no mandate was rejected: %v", err)
	}
}

// TestEngineEnqueueRejectsUnknownMandateRef refuses a claim of compliance with a mandate
// this node has never seen, rather than treating the claim as vacuously true.
func TestEngineEnqueueRejectsUnknownMandateRef(t *testing.T) {
	me := newMandateEngine(t)

	unknown := [32]byte{0xFF}
	entry := chain.ProvenanceEntry{
		Hash:       [32]byte{0x33},
		Submitter:  [16]byte{0x44},
		Timestamp:  time.Now().UnixNano(),
		Label:      "3cp:consensus-config",
		MandateRef: &unknown,
	}
	if err := me.engine.Enqueue(entry); err == nil {
		t.Fatal("an entry claiming compliance with an unknown mandate was accepted")
	} else if !errors.Is(err, validation.ErrMandateNotFound) {
		t.Errorf("got %v, want it to wrap ErrMandateNotFound", err)
	}
}

// TestEngineRecordMandateBodyRejectsUnsigned keeps the peer-ingress path as strict as the
// local one. This is how a node learns mandates it did not issue, so accepting an
// unsigned body here would undo the check SubmitMandate performs.
func TestEngineRecordMandateBodyRejectsUnsigned(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)
	mandate.Signature = nil
	mandate.ID = mandate.MandateID()

	if err := me.engine.RecordMandateBody(mandate); err == nil {
		t.Fatal("RecordMandateBody accepted an unsigned mandate body")
	}
	if _, ok := me.engine.MandateBody(mandate.ID); ok {
		t.Error("the rejected body was retained anyway")
	}
}

// TestEngineRecordMandateBodyAdmitsPeer is the peer path's happy case: a node that did
// not issue the mandate can still learn and enforce it.
func TestEngineRecordMandateBodyAdmitsPeer(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)

	if err := me.engine.RecordMandateBody(mandate); err != nil {
		t.Fatalf("RecordMandateBody: %v", err)
	}
	got, ok := me.engine.MandateBody(mandate.ID)
	if !ok {
		t.Fatal("the peer body was not retained")
	}
	if len(got.Rules) != 1 || got.Rules[0].EventClass != "3cp:consensus-config" {
		t.Error("the retained peer body lost its rules")
	}
}

// TestEngineMandateBodyIsACopy checks the accessor does not hand out a pointer into the
// engine's own state, which would let a caller mutate an enforceable mandate.
func TestEngineMandateBodyIsACopy(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)
	if err := me.engine.RecordMandateBody(mandate); err != nil {
		t.Fatalf("RecordMandateBody: %v", err)
	}

	got, ok := me.engine.MandateBody(mandate.ID)
	if !ok {
		t.Fatal("no body")
	}
	got.Rules = nil
	got.ValidUntil = 0

	again, ok := me.engine.MandateBody(mandate.ID)
	if !ok {
		t.Fatal("body disappeared")
	}
	if len(again.Rules) != 1 {
		t.Error("mutating the returned value changed the engine's retained mandate")
	}
	if again.ValidUntil != mandate.ValidUntil {
		t.Error("mutating the returned value changed the engine's retained validity window")
	}
}

// TestEngineCheckComplianceReportsMissingObligation is verification-time enforcement: a
// mandate that requires an event which never arrives is reported as a gap.
func TestEngineCheckComplianceReportsMissingObligation(t *testing.T) {
	me := newMandateEngine(t)

	// One mandatory rule with a one-off obligation and no matching anchored entry.
	now := time.Now()
	mandate := me.signedMandate(t, func(m *chain.MandateEntry) {
		m.ValidFrom = now.Add(-2 * time.Hour).UnixNano()
		m.ValidUntil = now.Add(2 * time.Hour).UnixNano()
		m.Rules = []chain.Rule{{
			EventClass:     "3cp:consensus-config",
			RequiredFields: []string{"Signature"},
			Mandatory:      true,
			// One event per hour of the audited window, so the report must contain
			// roughly one gap per hour rather than a single verdict.
			MaxDeferralSec: 3600,
		}}
	})
	if err := me.engine.SubmitMandate(mandate); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}

	window := validation.ComplianceWindow{
		StartTimestamp: now.Add(-24 * time.Hour).UnixNano(),
		EndTimestamp:   now.UnixNano(),
	}
	report, err := me.engine.CheckCompliance(mandate.ID, window)
	if err != nil {
		t.Fatalf("CheckCompliance: %v", err)
	}
	if report.TotalExpected == 0 {
		t.Fatal("no obligations were expected, so the rule is not being evaluated")
	}
	if report.TotalAnchored != 0 {
		t.Errorf("got %d anchored, want 0: no matching entry was ever submitted", report.TotalAnchored)
	}
	if len(report.Gaps) == 0 {
		t.Fatal("a wholly unhonoured mandate produced no gaps")
	}
	if report.ComplianceRate != 0 {
		t.Errorf("compliance rate is %v, want 0", report.ComplianceRate)
	}
}

// TestEngineCheckComplianceRejectsUnknownMandate checks the error path rather than
// returning an empty report, which would read as full compliance.
func TestEngineCheckComplianceRejectsUnknownMandate(t *testing.T) {
	me := newMandateEngine(t)

	now := time.Now()
	_, err := me.engine.CheckCompliance([32]byte{0xAB}, validation.ComplianceWindow{
		StartTimestamp: now.Add(-time.Hour).UnixNano(),
		EndTimestamp:   now.UnixNano(),
	})
	if err == nil {
		t.Fatal("checking an unknown mandate succeeded")
	}
	if !errors.Is(err, validation.ErrMandateNotFound) {
		t.Errorf("got %v, want it to wrap ErrMandateNotFound", err)
	}
}

// TestEngineCheckComplianceRejectsInvalidWindow checks the window is validated before any
// work is done, so a caller cannot ask a meaningless question and read the answer as
// compliance.
func TestEngineCheckComplianceRejectsInvalidWindow(t *testing.T) {
	me := newMandateEngine(t)
	mandate := me.signedMandate(t, nil)
	if err := me.engine.SubmitMandate(mandate); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}

	now := time.Now()
	if _, err := me.engine.CheckCompliance(mandate.ID, validation.ComplianceWindow{
		StartTimestamp: now.UnixNano(),
		EndTimestamp:   now.Add(-time.Hour).UnixNano(),
	}); err == nil {
		t.Fatal("a window ending before it starts was accepted")
	} else if !errors.Is(err, validation.ErrComplianceWindowInvalid) {
		t.Errorf("got %v, want it to wrap ErrComplianceWindowInvalid", err)
	}
}

// TestEngineEntriesInWindowDefaultsToWholeChain checks the cycle bounds are optional, so
// a caller who knows nothing about cycle numbering still scans everything.
func TestEngineEntriesInWindowDefaultsToWholeChain(t *testing.T) {
	me := newMandateEngine(t)

	me.engine.mu.Lock()
	me.engine.blocks = []chain.Block{
		{Index: 0, Anchored: []chain.ProvenanceEntry{{Hash: [32]byte{1}}}},
		{Index: 1, Anchored: []chain.ProvenanceEntry{{Hash: [32]byte{2}}}},
		{Index: 2, Anchored: []chain.ProvenanceEntry{{Hash: [32]byte{3}}}},
	}
	me.engine.mu.Unlock()

	if got := me.engine.EntriesInWindow(0, 0); len(got) != 3 {
		t.Errorf("unbounded window returned %d entries, want 3", len(got))
	}
	if got := me.engine.EntriesInWindow(1, 2); len(got) != 2 {
		t.Errorf("window 1..2 returned %d entries, want 2", len(got))
	}
	// start 2 reaches the end of a three-block chain, so only block 2 qualifies.
	if got := me.engine.EntriesInWindow(2, 0); len(got) != 1 {
		t.Errorf("open-ended window from cycle 2 returned %d entries, want 1", len(got))
	}
	if got := me.engine.EntriesInWindow(0, 1); len(got) != 2 {
		t.Errorf("window 0..1 returned %d entries, want 2", len(got))
	}
	if got := me.engine.EntriesInWindow(9, 9); len(got) != 0 {
		t.Errorf("window past the chain returned %d entries, want 0", len(got))
	}
}

// TestEngineCheckAllCompliance walks every known mandate, which is what a periodic audit
// job would call.
func TestEngineCheckAllCompliance(t *testing.T) {
	me := newMandateEngine(t)

	first := me.signedMandate(t, nil)
	if err := me.engine.SubmitMandate(first); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}
	second := me.signedMandate(t, func(m *chain.MandateEntry) {
		m.Version = 2
		m.PrevVersion = first.ID
		m.Rules = []chain.Rule{{EventClass: "3cp:anchor-config", Mandatory: false}}
	})
	if err := me.engine.SubmitMandate(second); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}

	now := time.Now()
	reports, err := me.engine.CheckAllCompliance(validation.ComplianceWindow{
		StartTimestamp: now.Add(-time.Hour).UnixNano(),
		EndTimestamp:   now.Add(time.Hour).UnixNano(),
	})
	if err != nil {
		t.Fatalf("CheckAllCompliance: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2", len(reports))
	}
	// The non-mandatory rule must not contribute an expectation.
	for _, r := range reports {
		if r.MandateID == second.ID && r.TotalExpected != 0 {
			t.Errorf("a recommended-only mandate reported %d expectations", r.TotalExpected)
		}
	}
}
