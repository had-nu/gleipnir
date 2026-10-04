// Mandate compliance tests — 3CP v2.0 §13, dual enforcement.
//
// TestMandateValidation covers submission-time structural validation.
// TestComplianceCheck covers verification-time detection of omissions.
package validation

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
)

const (
	day = int64(24 * time.Hour)
	// A fixed base so tests do not depend on wall-clock time.
	base = int64(1_700_000_000) * int64(time.Second)
)

// newTestMandate builds a mandate whose ID is computed, as the protocol requires.
func newTestMandate(t *testing.T, validFrom, validUntil int64, rules []chain.Rule) *chain.MandateEntry {
	t.Helper()
	m := &chain.MandateEntry{
		Authority:  [16]byte{1},
		Version:    1,
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
		Rules:      rules,
	}
	m.ID = m.MandateID()
	return m
}

// TestMandateIDCommitsToContents pins the identifier definition: BLAKE3-256 over the
// canonical CBOR excluding the signature. A stub returning zero would make every
// compliance report name an unidentifiable mandate.
func TestMandateIDCommitsToContents(t *testing.T) {
	m := newTestMandate(t, base, base+10*day, []chain.Rule{{EventClass: "release_gate", Mandatory: true}})

	if !m.VerifyHash() {
		t.Fatal("freshly built mandate must have a matching ID")
	}
	if m.ID == ([32]byte{}) {
		t.Fatal("MandateID must not be the zero value")
	}

	// The signature is excluded, so adding one must not change the ID.
	signed := *m
	signed.Signature = []byte("signature-bytes")
	if signed.MandateID() != m.ID {
		t.Error("MandateID must exclude the signature field")
	}

	// Every other field is covered.
	for _, mutate := range []func(*chain.MandateEntry){
		func(x *chain.MandateEntry) { x.Version++ },
		func(x *chain.MandateEntry) { x.ValidUntil++ },
		func(x *chain.MandateEntry) { x.Authority[0] ^= 0xFF },
		func(x *chain.MandateEntry) { x.Rules[0].EventClass = "other" },
		func(x *chain.MandateEntry) { x.Rules[0].Mandatory = false },
		func(x *chain.MandateEntry) { x.PolicyHash[0] ^= 0xFF },
		func(x *chain.MandateEntry) { x.Supersedes[0] ^= 0xFF },
	} {
		other := *m
		other.Rules = append([]chain.Rule(nil), m.Rules...)
		mutate(&other)
		if other.MandateID() == m.ID {
			t.Error("MandateID must change when a covered field changes")
		}
	}
}

// TestMandateCBORRoundTrip verifies the wire form and that a tampered body is rejected.
func TestMandateCBORRoundTrip(t *testing.T) {
	m := newTestMandate(t, base, base+10*day, []chain.Rule{{
		EventClass:     "release_gate",
		Mandatory:      true,
		RequiredFields: []string{"Approver"},
		MaxDeferralSec: 3600,
	}})

	encoded, err := chain.MarshalMandateEntry(m)
	if err != nil {
		t.Fatalf("MarshalMandateEntry: %v", err)
	}
	decoded, err := chain.UnmarshalMandateEntry(encoded)
	if err != nil {
		t.Fatalf("UnmarshalMandateEntry: %v", err)
	}
	if decoded.ID != m.ID || len(decoded.Rules) != 1 || decoded.Rules[0].EventClass != "release_gate" {
		t.Fatal("round trip must preserve the mandate")
	}

	tampered := *decoded
	tampered.Rules = append([]chain.Rule(nil), decoded.Rules...)
	tampered.Rules[0].Mandatory = false
	tamperedBytes, err := chain.MarshalMandateEntry(&tampered)
	if err != nil {
		t.Fatalf("MarshalMandateEntry(tampered): %v", err)
	}
	if _, err := chain.UnmarshalMandateEntry(tamperedBytes); !errors.Is(err, chain.ErrMandateHashMismatch) {
		t.Fatalf("want chain.ErrMandateHashMismatch, got %v", err)
	}
}

// TestMandateValidation covers submission-time enforcement of the five rules' mandate
// counterparts: reference resolution, validity window and required fields.
func TestMandateValidation(t *testing.T) {
	rules := []chain.Rule{{
		EventClass:     "release_gate",
		Mandatory:      true,
		RequiredFields: []string{"Approver", "Signature"},
	}}
	m := newTestMandate(t, base, base+10*day, rules)

	resolver := NewMandateResolver(nil)
	if err := resolver.Put(m); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v := NewMandateValidator(resolver)

	validEntry := func() *chain.ProvenanceEntry {
		return &chain.ProvenanceEntry{
			Hash:       [32]byte{9},
			Submitter:  [16]byte{2},
			Timestamp:  base + day,
			Label:      "release_gate",
			Approver:   &[16]byte{3},
			Signature:  []byte("sig"),
			MandateRef: &m.ID,
		}
	}

	t.Run("NoMandateRefIsAccepted", func(t *testing.T) {
		e := validEntry()
		e.MandateRef = nil
		if err := v.ValidateEntryAgainstMandates(e, e.Timestamp); err != nil {
			t.Fatalf("an entry making no compliance claim must be accepted, got %v", err)
		}
	})

	t.Run("CompliantEntryAccepted", func(t *testing.T) {
		e := validEntry()
		if err := v.ValidateEntryAgainstMandates(e, e.Timestamp); err != nil {
			t.Fatalf("want accepted, got %v", err)
		}
	})

	t.Run("UnknownMandateRefRejected", func(t *testing.T) {
		e := validEntry()
		unknown := [32]byte{0xFF}
		e.MandateRef = &unknown
		if err := v.ValidateEntryAgainstMandates(e, e.Timestamp); !errors.Is(err, ErrMandateNotFound) {
			t.Fatalf("want ErrMandateNotFound, got %v", err)
		}
	})

	t.Run("ExpiredMandateRejected", func(t *testing.T) {
		e := validEntry()
		e.Timestamp = base + 20*day // past ValidUntil
		if err := v.ValidateEntryAgainstMandates(e, e.Timestamp); !errors.Is(err, ErrMandateExpired) {
			t.Fatalf("want ErrMandateExpired, got %v", err)
		}
	})

	t.Run("NotYetActiveMandateRejected", func(t *testing.T) {
		e := validEntry()
		e.Timestamp = base - day // before ValidFrom
		if err := v.ValidateEntryAgainstMandates(e, e.Timestamp); !errors.Is(err, ErrMandateExpired) {
			t.Fatalf("want ErrMandateExpired, got %v", err)
		}
	})

	t.Run("MissingRequiredFieldRejected", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			mutate  func(*chain.ProvenanceEntry)
			missing string
		}{
			{"no Approver", func(e *chain.ProvenanceEntry) { e.Approver = nil }, "Approver"},
			{"no Signature", func(e *chain.ProvenanceEntry) { e.Signature = nil }, "Signature"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := validEntry()
				tc.mutate(e)
				err := v.ValidateEntryAgainstMandates(e, e.Timestamp)
				if !errors.Is(err, ErrMandateMissingRequiredField) {
					t.Fatalf("want ErrMandateMissingRequiredField, got %v", err)
				}
			})
		}
	})

	t.Run("OtherEventClassNotGoverned", func(t *testing.T) {
		e := validEntry()
		e.Label = "incident_classification"
		e.Approver = nil // would fail if the rule applied
		if err := v.ValidateEntryAgainstMandates(e, e.Timestamp); err != nil {
			t.Fatalf("a rule must only govern its own event class, got %v", err)
		}
	})

	t.Run("NilEntryRejected", func(t *testing.T) {
		if err := v.ValidateEntryAgainstMandates(nil, base); !errors.Is(err, ErrInvalidMandateEntry) {
			t.Fatalf("want ErrInvalidMandateEntry, got %v", err)
		}
	})
}

// TestMandateResolver covers version lineage and active-window resolution.
func TestMandateResolver(t *testing.T) {
	v1 := newTestMandate(t, base, base+10*day, []chain.Rule{{EventClass: "a", Mandatory: true}})

	v2 := *v1
	v2.Version = 2
	v2.PrevVersion = v1.ID
	v2.Supersedes = v1.ID
	v2.ValidUntil = base + 20*day
	v2.Rules = []chain.Rule{{EventClass: "b", Mandatory: true}}
	v2.ID = v2.MandateID()

	resolver := NewMandateResolver(nil)
	for _, m := range []*chain.MandateEntry{v1, &v2} {
		if err := resolver.Put(m); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	t.Run("ResolvesByID", func(t *testing.T) {
		got, ok := resolver.GetMandateByID(v2.ID)
		if !ok || got.Version != 2 {
			t.Fatalf("want version 2, got %+v ok=%v", got, ok)
		}
	})

	t.Run("SupersededVersionNotActive", func(t *testing.T) {
		active, err := resolver.GetActiveMandates(base + day)
		if err != nil {
			t.Fatalf("GetActiveMandates: %v", err)
		}
		if len(active) != 1 {
			t.Fatalf("a superseded mandate must not be reported active, got %d", len(active))
		}
		if active[0].ID != v2.ID {
			t.Fatal("the newest version must be the active one")
		}
	})

	t.Run("InactiveOutsideWindow", func(t *testing.T) {
		active, err := resolver.GetActiveMandates(base + 30*day)
		if err != nil {
			t.Fatalf("GetActiveMandates: %v", err)
		}
		if len(active) != 0 {
			t.Fatalf("want no active mandates past ValidUntil, got %d", len(active))
		}
	})

	t.Run("NeverExpiresWhenValidUntilZero", func(t *testing.T) {
		forever := newTestMandate(t, base, 0, []chain.Rule{{EventClass: "c", Mandatory: true}})
		r := NewMandateResolver([]chain.MandateEntry{*forever})
		active, err := r.GetActiveMandates(base + 3650*day)
		if err != nil {
			t.Fatalf("GetActiveMandates: %v", err)
		}
		if len(active) != 1 {
			t.Fatalf("ValidUntil=0 must mean never expires, got %d active", len(active))
		}
	})

	t.Run("PutRecomputesID", func(t *testing.T) {
		lying := *v1
		lying.ID = [32]byte{0xDE, 0xAD} // claims an ID its contents do not produce
		r := NewMandateResolver(nil)
		if err := r.Put(&lying); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if _, ok := r.GetMandateByID([32]byte{0xDE, 0xAD}); ok {
			t.Error("a mandate must not be resolvable under an ID its contents do not produce")
		}
		if _, ok := r.GetMandateByID(v1.ID); !ok {
			t.Error("the recomputed ID must be the one recorded")
		}
	})

	t.Run("AllIsDeterministic", func(t *testing.T) {
		first := resolver.All()
		for i := 0; i < 5; i++ {
			again := resolver.All()
			for j := range first {
				if first[j].ID != again[j].ID {
					t.Fatal("All must return a stable order")
				}
			}
		}
	})
}

// TestComplianceCheck is the core of the feature: does the chain satisfy the mandate?
func TestComplianceCheck(t *testing.T) {
	window := ComplianceWindow{
		StartTimestamp: base,
		EndTimestamp:   base + 4*day,
		StartCycle:     0,
		EndCycle:       100,
	}

	rules := []chain.Rule{{
		EventClass:     "release_gate",
		Description:    "every release must be gated",
		Mandatory:      true,
		RequiredFields: []string{"Approver"},
		MaxDeferralSec: 86400, // one event per day
	}}
	mandate := newTestMandate(t, base, base+30*day, rules)

	resolver := NewMandateResolver(nil)
	if err := resolver.Put(mandate); err != nil {
		t.Fatalf("Put: %v", err)
	}
	checker := NewComplianceChecker(resolver)

	releaseEntry := func(ts int64) chain.ProvenanceEntry {
		return chain.ProvenanceEntry{
			Hash:      [32]byte{byte(ts % 251)},
			Submitter: [16]byte{2},
			Timestamp: ts,
			Label:     "release_gate",
			Approver:  &[16]byte{3},
		}
	}

	// The window spans four one-day buckets. Expectations are half-open [start, end),
	// so place each entry unambiguously inside its own bucket rather than on a
	// boundary: an entry at exactly the window end falls outside it.
	bucket0 := base + int64(time.Hour)
	bucket1 := base + 25*int64(time.Hour)
	bucket2 := base + 49*int64(time.Hour)
	bucket3 := base + 73*int64(time.Hour)

	t.Run("FullyCompliant", func(t *testing.T) {
		entries := []chain.ProvenanceEntry{
			releaseEntry(bucket0), releaseEntry(bucket1),
			releaseEntry(bucket2), releaseEntry(bucket3),
		}
		report, err := checker.CheckComplianceMandate(mandate.ID, window, entries)
		if err != nil {
			t.Fatalf("CheckComplianceMandate: %v", err)
		}
		if report.TotalExpected != 4 {
			t.Fatalf("want 4 expectations (one per day), got %d", report.TotalExpected)
		}
		if report.TotalAnchored != 4 {
			t.Fatalf("want 4 anchored, got %d", report.TotalAnchored)
		}
		if report.ComplianceRate != 1.0 {
			t.Fatalf("want rate 1.0, got %f", report.ComplianceRate)
		}
		if len(report.Gaps) != 0 {
			t.Fatalf("want no gaps, got %d: %+v", len(report.Gaps), report.Gaps)
		}
	})

	t.Run("OmissionIsDetected", func(t *testing.T) {
		// Bucket 2 has no release: a silent omission must be visible, and exactly one.
		entries := []chain.ProvenanceEntry{
			releaseEntry(bucket0), releaseEntry(bucket1), releaseEntry(bucket3),
		}
		report, err := checker.CheckComplianceMandate(mandate.ID, window, entries)
		if err != nil {
			t.Fatalf("CheckComplianceMandate: %v", err)
		}
		if len(report.Gaps) != 1 {
			t.Fatalf("want exactly 1 gap, got %d: %+v", len(report.Gaps), report.Gaps)
		}
		if report.Gaps[0].Status != ComplianceStatusMissing {
			t.Fatalf("want status %q, got %q", ComplianceStatusMissing, report.Gaps[0].Status)
		}
		if report.Gaps[0].EventClass != "release_gate" {
			t.Fatalf("gap must name the event class, got %q", report.Gaps[0].EventClass)
		}
		if report.Gaps[0].RuleIndex != 0 {
			t.Fatalf("gap must name the rule index, got %d", report.Gaps[0].RuleIndex)
		}
		if report.ComplianceRate != 0.75 {
			t.Fatalf("want rate 0.75, got %f", report.ComplianceRate)
		}
	})

	// The security-critical property: an operator who omits the compliance claim must
	// not thereby evade the obligation. Matching on MandateRef would let them.
	t.Run("OmittingMandateRefDoesNotEvade", func(t *testing.T) {
		entries := []chain.ProvenanceEntry{
			releaseEntry(bucket0), releaseEntry(bucket1), releaseEntry(bucket3),
		}
		for i := range entries {
			entries[i].MandateRef = nil // claim nothing
		}
		report, err := checker.CheckComplianceMandate(mandate.ID, window, entries)
		if err != nil {
			t.Fatalf("CheckComplianceMandate: %v", err)
		}
		if len(report.Gaps) != 1 {
			t.Fatalf("omitting MandateRef must not hide the omission, got %d gaps", len(report.Gaps))
		}
	})

	t.Run("PresentButIncompleteIsDistinct", func(t *testing.T) {
		incomplete := releaseEntry(bucket2)
		incomplete.Approver = nil
		entries := []chain.ProvenanceEntry{
			releaseEntry(bucket0), releaseEntry(bucket1),
			incomplete, releaseEntry(bucket3),
		}
		report, err := checker.CheckComplianceMandate(mandate.ID, window, entries)
		if err != nil {
			t.Fatalf("CheckComplianceMandate: %v", err)
		}
		if len(report.Gaps) != 1 {
			t.Fatalf("want 1 gap, got %d", len(report.Gaps))
		}
		gap := report.Gaps[0]
		if gap.Status != ComplianceStatusMissingFields {
			t.Fatalf("want status %q, got %q", ComplianceStatusMissingFields, gap.Status)
		}
		if len(gap.MissingFields) != 1 || gap.MissingFields[0] != "Approver" {
			t.Fatalf("gap must list the missing field, got %v", gap.MissingFields)
		}
		if report.TotalAnchored != 3 {
			t.Fatalf("an incomplete entry must not count as anchored, got %d", report.TotalAnchored)
		}
	})

	// Expectations are half-open, so an entry exactly at the window end is outside it
	// and one before the window must not be credited to any bucket.
	t.Run("WindowBoundariesAreHalfOpen", func(t *testing.T) {
		entries := []chain.ProvenanceEntry{
			releaseEntry(base),                    // first instant, inside bucket 0
			releaseEntry(base + 4*day),            // window end, outside
			releaseEntry(base - int64(time.Hour)), // before the window, outside
		}
		report, err := checker.CheckComplianceMandate(mandate.ID, window, entries)
		if err != nil {
			t.Fatalf("CheckComplianceMandate: %v", err)
		}
		if report.TotalAnchored != 1 {
			t.Fatalf("only the entry at the window start is inside, got %d anchored", report.TotalAnchored)
		}
	})

	// A mandate may be authored with an absurd deferral. It must degrade to a single
	// expectation rather than overflowing the nanosecond conversion into a zero or
	// negative step, which would spin or silently mis-bucket the window.
	t.Run("AbsurdDeferralDoesNotOverflow", func(t *testing.T) {
		for _, deferral := range []uint64{math.MaxUint64, math.MaxUint64 / 2, uint64(math.MaxInt64)} {
			absurd := newTestMandate(t, base, base+30*day, []chain.Rule{{
				EventClass:     "release_gate",
				Mandatory:      true,
				MaxDeferralSec: deferral,
			}})
			r := NewMandateResolver(nil)
			if err := r.Put(absurd); err != nil {
				t.Fatalf("Put: %v", err)
			}
			report, err := NewComplianceChecker(r).CheckComplianceMandate(absurd.ID, window, nil)
			if err != nil {
				t.Fatalf("deferral %d: %v", deferral, err)
			}
			if report.TotalExpected != 1 {
				t.Fatalf("deferral %d: want 1 expectation, got %d", deferral, report.TotalExpected)
			}
		}
	})

	t.Run("NonRecommendedRulesAreNotObligations", func(t *testing.T) {
		advisory := newTestMandate(t, base, base+30*day, []chain.Rule{{
			EventClass: "advisory_event",
			Mandatory:  false,
		}})
		r := NewMandateResolver(nil)
		if err := r.Put(advisory); err != nil {
			t.Fatalf("Put: %v", err)
		}
		report, err := NewComplianceChecker(r).CheckComplianceMandate(advisory.ID, window, nil)
		if err != nil {
			t.Fatalf("CheckComplianceMandate: %v", err)
		}
		if report.TotalExpected != 0 || len(report.Gaps) != 0 {
			t.Fatalf("a non-mandatory rule must create no expectations, got %d/%d",
				report.TotalExpected, len(report.Gaps))
		}
	})

	t.Run("UnknownMandateRejected", func(t *testing.T) {
		if _, err := checker.CheckComplianceMandate([32]byte{0xFF}, window, nil); !errors.Is(err, ErrMandateNotFound) {
			t.Fatalf("want ErrMandateNotFound, got %v", err)
		}
	})

	t.Run("InvalidWindowRejected", func(t *testing.T) {
		for _, w := range []ComplianceWindow{
			{StartTimestamp: base, EndTimestamp: base - 1},
			{StartTimestamp: 0, EndTimestamp: base},
			{StartTimestamp: base, EndTimestamp: base + day, StartCycle: 10, EndCycle: 5},
		} {
			if _, err := checker.CheckComplianceMandate(mandate.ID, w, nil); !errors.Is(err, ErrComplianceWindowInvalid) {
				t.Fatalf("window %+v: want ErrComplianceWindowInvalid, got %v", w, err)
			}
		}
	})

	// MaxDeferralSec == 0 means "immediate", which must be modelled as a single
	// expectation rather than one per nanosecond.
	t.Run("ZeroDeferralIsOneExpectation", func(t *testing.T) {
		immediate := newTestMandate(t, base, base+30*day, []chain.Rule{{
			EventClass:     "incident",
			Mandatory:      true,
			RequiredFields: []string{"Approver"},
		}})
		r := NewMandateResolver(nil)
		if err := r.Put(immediate); err != nil {
			t.Fatalf("Put: %v", err)
		}
		c := NewComplianceChecker(r)

		report, err := c.CheckComplianceMandate(immediate.ID, window, nil)
		if err != nil {
			t.Fatalf("CheckComplianceMandate: %v", err)
		}
		if report.TotalExpected != 1 {
			t.Fatalf("want 1 expectation for the whole window, got %d", report.TotalExpected)
		}

		entry := chain.ProvenanceEntry{
			Hash: [32]byte{7}, Submitter: [16]byte{2},
			Timestamp: base + day, Label: "incident", Approver: &[16]byte{3},
		}
		report, err = c.CheckComplianceMandate(immediate.ID, window, []chain.ProvenanceEntry{entry})
		if err != nil {
			t.Fatalf("CheckComplianceMandate: %v", err)
		}
		if report.TotalAnchored != 1 || len(report.Gaps) != 0 {
			t.Fatalf("one event anywhere in the window must satisfy the rule, got %d/%d",
				report.TotalAnchored, len(report.Gaps))
		}
	})

	t.Run("CheckAllMandatesIsOrdered", func(t *testing.T) {
		reports, err := checker.CheckAllMandates(window, nil)
		if err != nil {
			t.Fatalf("CheckAllMandates: %v", err)
		}
		if len(reports) != len(resolver.All()) {
			t.Fatalf("want one report per mandate, got %d", len(reports))
		}
		for i := 1; i < len(reports); i++ {
			if bytesLess(reports[i].MandateID[:], reports[i-1].MandateID[:]) {
				t.Fatal("reports must be ordered by mandate ID")
			}
		}
	})
}

// The checker must be a pure function of (mandate, window, chain): rerunning it, or
// running it on a copy, must reach the same conclusion. That is what makes the result
// usable as evidence by a third party.
func TestComplianceCheckIsDeterministic(t *testing.T) {
	mandate := newTestMandate(t, base, base+30*day, []chain.Rule{{
		EventClass: "release_gate", Mandatory: true, MaxDeferralSec: 86400,
	}})
	resolver := NewMandateResolver([]chain.MandateEntry{*mandate})
	checker := NewComplianceChecker(resolver)

	window := ComplianceWindow{StartTimestamp: base, EndTimestamp: base + 3*day}
	entries := []chain.ProvenanceEntry{{
		Hash: [32]byte{1}, Submitter: [16]byte{2},
		Timestamp: base + day, Label: "release_gate", Approver: &[16]byte{3},
	}}

	first, err := checker.CheckComplianceMandate(mandate.ID, window, entries)
	if err != nil {
		t.Fatalf("CheckComplianceMandate: %v", err)
	}

	for i := 0; i < 10; i++ {
		again, err := checker.CheckComplianceMandate(mandate.ID, window, entries)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if again.TotalExpected != first.TotalExpected ||
			again.TotalAnchored != first.TotalAnchored ||
			again.ComplianceRate != first.ComplianceRate ||
			len(again.Gaps) != len(first.Gaps) {
			t.Fatalf("run %d diverged from the first run", i)
		}
	}

	// A fresh checker over a fresh resolver must agree too.
	fresh := NewComplianceChecker(NewMandateResolver([]chain.MandateEntry{*mandate}))
	independent, err := fresh.CheckComplianceMandate(mandate.ID, window, entries)
	if err != nil {
		t.Fatalf("independent check: %v", err)
	}
	if independent.TotalAnchored != first.TotalAnchored || len(independent.Gaps) != len(first.Gaps) {
		t.Fatal("an independent verifier must reach the same conclusion")
	}
}
