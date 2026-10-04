// Submission-time mandate validation — 3CP v2.0 §13, dual enforcement, first half.
//
// When a submitter claims compliance by setting MandateRef, the protocol checks the
// claim structurally: the mandate must exist, be in force at the entry's timestamp, and
// have every field the referenced rules require. This stops "I was complying with
// mandate X" claims that fail the most basic requirements.
//
// It deliberately cannot detect omitted events. The protocol never sees events that
// were never submitted, so that check belongs to verification time and lives in
// compliance_checker.go.
package validation

import (
	"fmt"

	"github.com/had-nu/gleipnir/pkg/chain"
)

// MandateValidator validates provenance entries against the mandates they reference.
type MandateValidator struct {
	resolver *MandateResolver
}

// NewMandateValidator creates a validator over a resolver.
func NewMandateValidator(resolver *MandateResolver) *MandateValidator {
	return &MandateValidator{resolver: resolver}
}

// ValidateEntryAgainstMandates checks an entry that claims compliance with a mandate.
//
// An entry with no MandateRef makes no claim and is accepted: most entries in a
// provenance chain are not governed by any mandate, and rejecting them would make the
// mandate mechanism unusable.
func (v *MandateValidator) ValidateEntryAgainstMandates(entry *chain.ProvenanceEntry, timestamp int64) error {
	if entry == nil {
		return ErrInvalidMandateEntry
	}
	if entry.MandateRef == nil {
		return nil
	}

	mandate, ok := v.resolver.GetMandateByID(*entry.MandateRef)
	if !ok {
		return fmt.Errorf("%w: %x", ErrMandateNotFound, *entry.MandateRef)
	}

	if !mandate.IsActiveAt(timestamp) {
		return fmt.Errorf("%w: mandate %x valid [%d,%d], entry at %d",
			ErrMandateExpired, mandate.ID, mandate.ValidFrom, mandate.ValidUntil, timestamp)
	}

	// Only rules the entry's own event class falls under apply; a mandate may govern
	// several event classes and an entry is not answerable to all of them.
	for i := range mandate.Rules {
		rule := &mandate.Rules[i]
		if !entryMatchesRule(entry, rule) {
			continue
		}
		if err := v.validateRule(rule, entry); err != nil {
			return err
		}
	}
	return nil
}

// validateRule enforces one rule's required fields and anchoring obligation.
func (v *MandateValidator) validateRule(rule *chain.Rule, entry *chain.ProvenanceEntry) error {
	for _, field := range rule.RequiredFields {
		if !entryHasField(entry, field) {
			return fmt.Errorf("%w: rule %q requires %s", ErrMandateMissingRequiredField, rule.EventClass, field)
		}
	}
	return nil
}

// entryMatchesRule reports whether a rule governs this entry's event class.
//
// A ProvenanceEntry carries its event class in Label. A rule with an empty EventClass
// is treated as applying to every entry, which lets a mandate express blanket field
// requirements without inventing event classes.
func entryMatchesRule(entry *chain.ProvenanceEntry, rule *chain.Rule) bool {
	if rule.EventClass == "" {
		return true
	}
	return entry.Label == rule.EventClass
}

// entryHasField reports whether an entry populates the named field.
//
// Unknown field names are treated as satisfied: a rule may name a field this entry
// schema does not carry, and failing closed on those would reject every entry. The
// mandated field set is fixed, so an unrecognised name is a policy authoring error
// rather than a compliance signal.
func entryHasField(entry *chain.ProvenanceEntry, field string) bool {
	switch field {
	case "Approver":
		return entry.Approver != nil
	case "Reference":
		return entry.Reference != nil
	case "Signature":
		return len(entry.Signature) > 0
	case "MandateRef":
		return entry.MandateRef != nil
	case "Label":
		return entry.Label != ""
	case "Submitter":
		return entry.Submitter != [16]byte{}
	case "Hash":
		return entry.Hash != [32]byte{}
	default:
		return true
	}
}
