// Verification-time mandate compliance — 3CP v2.0 §13, dual enforcement, second half.
//
// This is the protocol's novelty. The chain is compared against the obligation the
// mandate declared, and the comparison is a pure function of (mandate, window, chain),
// so any third party can rerun it and reach the same conclusion.
//
// The critical property is what the check does NOT trust. It does not consult
// entry.MandateRef: matching on that field would let an operator evade every
// mandatory rule by simply omitting the reference. Expectations are derived from the
// mandate's own rules and matched against every anchored entry by event class, so
// omitting an event — or omitting the claim that it happened — are both detectable.
//
// What it cannot do is prove that an event never occurred in the world. It proves the
// chain lacks evidence of it, which is the whole point: without a mandate the two are
// indistinguishable.
package validation

import (
	"fmt"
	"math"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
)

// Compliance status values, matching compliance-gap in spec/schemas/mandate.cddl.
const (
	ComplianceStatusAnchored      = "anchored"
	ComplianceStatusMissing       = "missing"
	ComplianceStatusMissingFields = "missing_fields"
)

// ComplianceWindow is the interval an auditor asks about, expressed both in wall-clock
// and in cycle range. Cycles bound the scan; timestamps bound the expectations.
type ComplianceWindow struct {
	StartTimestamp int64
	EndTimestamp   int64
	StartCycle     uint64
	EndCycle       uint64
}

// Validate rejects a window that cannot describe an interval.
func (w ComplianceWindow) Validate() error {
	if w.StartTimestamp <= 0 || w.EndTimestamp <= 0 {
		return fmt.Errorf("%w: timestamps must be non-zero UnixNano", ErrComplianceWindowInvalid)
	}
	if w.EndTimestamp < w.StartTimestamp {
		return fmt.Errorf("%w: end %d before start %d",
			ErrComplianceWindowInvalid, w.EndTimestamp, w.StartTimestamp)
	}
	if w.EndCycle < w.StartCycle {
		return fmt.Errorf("%w: end cycle %d before start cycle %d",
			ErrComplianceWindowInvalid, w.EndCycle, w.StartCycle)
	}
	return nil
}

// ComplianceGap is one detected omission (spec/schemas/mandate.cddl compliance-gap).
type ComplianceGap struct {
	MandateID     [32]byte
	RuleIndex     int
	EventClass    string
	WindowStart   int64
	WindowEnd     int64
	Status        string
	Details       string
	MissingFields []string
}

// ComplianceReport is the result of verifying one mandate over one window
// (compliance-verification in spec/schemas/mandate.cddl).
type ComplianceReport struct {
	MandateID      [32]byte
	MandateLabel   string
	Window         ComplianceWindow
	TotalExpected  int
	TotalAnchored  int
	Gaps           []ComplianceGap
	ComplianceRate float64
	Timestamp      int64
}

// ComplianceChecker verifies a chain against a mandate.
type ComplianceChecker struct {
	resolver *MandateResolver
}

// NewComplianceChecker creates a checker over a resolver.
func NewComplianceChecker(resolver *MandateResolver) *ComplianceChecker {
	return &ComplianceChecker{resolver: resolver}
}

// CheckComplianceMandate verifies a single mandate over a window.
func (c *ComplianceChecker) CheckComplianceMandate(
	mandateID [32]byte,
	window ComplianceWindow,
	entries []chain.ProvenanceEntry,
) (*ComplianceReport, error) {
	if err := window.Validate(); err != nil {
		return nil, err
	}

	mandate, ok := c.resolver.GetMandateByID(mandateID)
	if !ok {
		return nil, fmt.Errorf("%w: %x", ErrMandateNotFound, mandateID)
	}

	report := &ComplianceReport{
		MandateID:    mandateID,
		MandateLabel: mandateLabel(mandate),
		Window:       window,
		Timestamp:    time.Now().UnixNano(),
	}

	for i := range mandate.Rules {
		rule := &mandate.Rules[i]
		if !rule.Mandatory {
			continue // recommended, not an obligation
		}

		for _, expectation := range expectedEvents(rule, window) {
			report.TotalExpected++
			matched, missingFields := findMatchingEntry(rule, expectation, entries)
			if matched != nil && len(missingFields) == 0 {
				report.TotalAnchored++
				continue
			}

			gap := ComplianceGap{
				MandateID:   mandateID,
				RuleIndex:   i,
				EventClass:  rule.EventClass,
				WindowStart: expectation.start,
				WindowEnd:   expectation.end,
				Status:      ComplianceStatusMissing,
				Details:     fmt.Sprintf("no entry labelled %q anchored in this window", rule.EventClass),
			}
			if matched != nil {
				gap.Status = ComplianceStatusMissingFields
				gap.MissingFields = missingFields
				gap.Details = fmt.Sprintf("entry labelled %q is missing required fields %v",
					rule.EventClass, missingFields)
			}
			report.Gaps = append(report.Gaps, gap)
		}
	}

	if report.TotalExpected > 0 {
		report.ComplianceRate = float64(report.TotalAnchored) / float64(report.TotalExpected)
	}
	return report, nil
}

// CheckAllMandates verifies every mandate known to the resolver over a window, ordered
// by mandate ID so the output is reproducible.
func (c *ComplianceChecker) CheckAllMandates(
	window ComplianceWindow,
	entries []chain.ProvenanceEntry,
) ([]*ComplianceReport, error) {
	if err := window.Validate(); err != nil {
		return nil, err
	}

	all := c.resolver.All()
	reports := make([]*ComplianceReport, 0, len(all))
	for _, m := range all {
		report, err := c.CheckComplianceMandate(m.ID, window, entries)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// expectation is one interval in which at least one matching event must be anchored.
type expectation struct {
	start int64
	end   int64
}

// expectedEvents partitions the window into the intervals a rule obliges the operator
// to fill.
//
// MaxDeferralSec is the operator's permitted delay between consecutive events of the
// class, so the window is cut into buckets of that length and each bucket expects at
// least one event. MaxDeferralSec == 0 means "immediate", which is modelled as a single
// expectation spanning the whole window: demanding one event per nanosecond would make
// every such mandate unachievable.
func expectedEvents(rule *chain.Rule, window ComplianceWindow) []expectation {
	start := window.StartTimestamp
	end := window.EndTimestamp

	if rule.MaxDeferralSec == 0 {
		return []expectation{{start: start, end: end}}
	}

	// Bound the deferral before converting to nanoseconds. MaxDeferralSec is authored in
	// a signed mandate, but a value near 2^64 would overflow the multiplication and
	// yield a negative or zero step, which would then either spin or silently collapse
	// the whole window into one expectation. Anything that large is treated as "no
	// meaningful bound", i.e. a single expectation for the window.
	const maxDeferralSec = uint64(math.MaxInt64) / uint64(time.Second)
	if rule.MaxDeferralSec > maxDeferralSec {
		return []expectation{{start: start, end: end}}
	}
	step := int64(rule.MaxDeferralSec) * int64(time.Second)
	if step <= 0 {
		return []expectation{{start: start, end: end}}
	}

	var out []expectation
	for bucketStart := start; bucketStart < end; bucketStart += step {
		bucketEnd := bucketStart + step
		if bucketEnd > end {
			bucketEnd = end
		}
		out = append(out, expectation{start: bucketStart, end: bucketEnd})
	}
	return out
}

// findMatchingEntry locates an entry of the rule's event class inside one expectation.
//
// It returns the entry and any required fields it failed to carry. An entry that is
// present but incomplete is a different failure from an absent one — the evidence
// exists but is not compliant — and the report distinguishes them.
func findMatchingEntry(
	rule *chain.Rule,
	exp expectation,
	entries []chain.ProvenanceEntry,
) (*chain.ProvenanceEntry, []string) {
	var found *chain.ProvenanceEntry
	var incomplete []string

	for i := range entries {
		entry := &entries[i]
		if !entryMatchesRule(entry, rule) {
			continue
		}
		if entry.Timestamp < exp.start || entry.Timestamp >= exp.end {
			continue
		}

		missing := missingFields(rule, entry)
		if len(missing) == 0 {
			return entry, nil
		}
		if found == nil {
			found = entry
			incomplete = missing
		}
	}

	return found, incomplete
}

// missingFields lists a rule's required fields that an entry does not carry.
func missingFields(rule *chain.Rule, entry *chain.ProvenanceEntry) []string {
	if len(rule.RequiredFields) == 0 {
		return nil
	}
	var missing []string
	for _, field := range rule.RequiredFields {
		if !entryHasField(entry, field) {
			missing = append(missing, field)
		}
	}
	return missing
}

// mandateLabel is the entry label a mandate is submitted under.
func mandateLabel(mandate *chain.MandateEntry) string {
	return chain.MandateLabel
}
