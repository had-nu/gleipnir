// Mandate admission and compliance — 3CP v2.0 §15.
//
// This wires the second half of the gap that pkg/validation implements. The
// verification core exists; nothing called it. Three things were missing:
//
//   - Mandate bodies were never admitted, so the resolver stayed empty and no mandate
//     could ever be found, enforced or audited.
//   - Enqueue did not check entries against the mandates they claim to satisfy, so a
//     submitter could assert compliance and be believed.
//   - There was no way to ask whether the chain had honoured a mandate.
//
// A ProvenanceEntry anchors only a hash and a label, so a mandate body cannot be
// recovered from the chain later. Bodies are retained in memory, and peers learn them
// out of band through RecordMandateBody, the same arrangement key rotation uses.
package consensus

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/validation"
)

// initMandatesLocked wires the mandate resolver, submission validator and compliance
// checker. Called once during construction, before the engine is shared across
// goroutines.
func (e *Engine) initMandatesLocked() {
	resolver := validation.NewMandateResolver(nil)
	e.mandateResolver = resolver
	e.mandateValidator = validation.NewMandateValidator(resolver)
	e.complianceChecker = validation.NewComplianceChecker(resolver)
	e.mandateBodies = make(map[[32]byte]*chain.MandateEntry)
}

// MandateResolver exposes the engine's mandate resolver.
func (e *Engine) MandateResolver() *validation.MandateResolver {
	return e.mandateResolver
}

// MandateValidator exposes the engine's submission-time mandate validator.
func (e *Engine) MandateValidator() *validation.MandateValidator {
	return e.mandateValidator
}

// ComplianceChecker exposes the engine's compliance checker.
func (e *Engine) ComplianceChecker() *validation.ComplianceChecker {
	return e.complianceChecker
}

// mandateAuthorityLookupLocked resolves a RootID to its ML-DSA-65 verifying key.
//
// The validator set is consulted first, then network state, so a mandate may be issued
// by any node whose key the chain has learned rather than only by a consensus
// validator. Both maps are keyed differently: the validator set holds typed records,
// network state is keyed by hex-encoded UID.
//
// A node recorded in network state without a key yet is reported as unresolvable rather
// than resolved to a zero key. Handing back an all-zero key would make verification fail
// with a signature error instead of the more useful "no registered key", and would
// quietly make such a node unusable as an authority.
//
// The caller must hold e.mu.
func (e *Engine) mandateAuthorityLookupLocked(rootID [16]byte) ([]byte, bool) {
	for _, v := range e.state.ValidatorSet {
		if v.ValidatorID == rootID {
			return v.Dilithium3PK[:], true
		}
	}
	if node, ok := e.state.Nodes[hex.EncodeToString(rootID[:])]; ok {
		if node.Dilithium3PK == ([identity.Dilithium3PublicKeySize]byte{}) {
			return nil, false
		}
		return node.Dilithium3PK[:], true
	}
	return nil, false
}

// SubmitMandate installs a mandate, verifies that it is authentic, and enqueues it for
// anchoring.
//
// Authenticity is checked before anything is queued. A mandate that names an Authority
// it cannot prove possession of would otherwise become enforceable policy for every
// entry that references it, so an unsigned or wrongly-signed mandate is refused here
// rather than at verification time, where the damage would already be done.
//
// The caller must NOT hold e.mu.
func (e *Engine) SubmitMandate(mandate *chain.MandateEntry) error {
	if mandate == nil {
		return chain.ErrMandateHashMismatch
	}

	e.mu.Lock()
	lookup := func(rootID [16]byte) ([]byte, bool) { return e.mandateAuthorityLookupLocked(rootID) }
	err := validation.ValidateMandateAuthority(mandate, lookup)
	if err != nil {
		e.mu.Unlock()
		return err
	}

	// Put recomputes the identifier and only rejects a nil mandate, so this cannot fail
	// in practice. It is checked rather than discarded anyway: a silent failure here would
	// leave the body retained in mandateBodies while absent from the resolver, so the
	// mandate would be retrievable by ID yet unenforceable and invisible to an auditor.
	if err := e.mandateResolver.Put(mandate); err != nil {
		e.mu.Unlock()
		return fmt.Errorf("registering mandate %x: %w", mandate.ID, err)
	}

	// Only an authenticated mandate becomes an enforceable one. Peers have not seen this
	// body yet, so they cannot validate submissions that reference it until
	// RecordMandateBody hands it to them.
	e.mandateBodies[mandate.ID] = mandate
	e.mu.Unlock()

	// The body is deliberately not gossiped. GossipChannel carries provenance entries,
	// and a mandate body is not one; adding a method to that interface would break every
	// implementation for no gain. Peers obtain the body out of band and hand it to
	// RecordMandateBody, which is how key rotation bodies are distributed too.
	return e.Enqueue(chain.ProvenanceEntry{
		Hash:       mandate.ID,
		Submitter:  mandate.Authority,
		Timestamp:  mandate.ValidFrom,
		Label:      chain.MandateLabel,
		MandateRef: &mandate.ID,
	})
}

// RecordMandateBody registers a mandate body received from a peer so this node can
// enforce and audit it.
//
// Peers cannot learn mandate bodies from the chain, since a ProvenanceEntry anchors only
// a hash. Without this, a submission validated here would be rejected everywhere else
// for referencing an unknown mandate, and a compliance query would report no gap for a
// mandate the node has in fact seen. Bodies are keyed by mandate ID.
//
// The caller must NOT hold e.mu.
func (e *Engine) RecordMandateBody(mandate *chain.MandateEntry) error {
	if mandate == nil {
		return chain.ErrMandateHashMismatch
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	lookup := func(rootID [16]byte) ([]byte, bool) { return e.mandateAuthorityLookupLocked(rootID) }
	if err := validation.ValidateMandateAuthority(mandate, lookup); err != nil {
		return err
	}

	clone := *mandate
	e.mandateBodies[clone.ID] = &clone
	return e.mandateResolver.Put(&clone)
}

// MandateBody returns a previously registered mandate body.
func (e *Engine) MandateBody(id [32]byte) (*chain.MandateEntry, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	body, ok := e.mandateBodies[id]
	if !ok {
		return nil, false
	}
	clone := *body
	return &clone, true
}

// ActiveMandates returns the mandates in force at a timestamp. A zero timestamp means
// now.
func (e *Engine) ActiveMandates(timestamp int64) ([]*chain.MandateEntry, error) {
	if timestamp == 0 {
		timestamp = time.Now().UnixNano()
	}
	return e.mandateResolver.GetActiveMandates(timestamp)
}

// CheckCompliance verifies one mandate over a window, gathering the entries from this
// node's own blocks.
//
// The checker does not read the chain itself, so the window has to be turned into a
// concrete entry list here. That is also why the window carries cycle bounds: cycles
// bound which blocks are read at all, while timestamps bound when the obligations were
// due. A caller that supplies only timestamps scans the whole chain.
func (e *Engine) CheckCompliance(
	mandateID [32]byte,
	window validation.ComplianceWindow,
) (*validation.ComplianceReport, error) {
	entries := e.EntriesInWindow(window.StartCycle, window.EndCycle)
	return e.complianceChecker.CheckComplianceMandate(mandateID, window, entries)
}

// CheckAllCompliance verifies every known mandate over a window.
func (e *Engine) CheckAllCompliance(
	window validation.ComplianceWindow,
) ([]*validation.ComplianceReport, error) {
	entries := e.EntriesInWindow(window.StartCycle, window.EndCycle)
	return e.complianceChecker.CheckAllMandates(window, entries)
}

// EntriesInWindow returns every anchored entry in the inclusive cycle range. A zero
// bound is treated as "from the start" or "to the end" respectively, so a caller that
// knows nothing about the cycle numbering still gets the whole chain.
func (e *Engine) EntriesInWindow(startCycle, endCycle uint64) []chain.ProvenanceEntry {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]chain.ProvenanceEntry, 0, len(e.pending))
	for i := range e.blocks {
		block := &e.blocks[i]
		if block.Index < startCycle {
			continue
		}
		if endCycle > 0 && block.Index > endCycle {
			break
		}
		out = append(out, block.Anchored...)
	}
	return out
}

// processMandateEntriesLocked admits every mandate anchored in this cycle's batch.
//
// Mandates were already authenticated when their body was registered; this is the point
// at which they become anchored facts. A body that is missing or fails re-validation is
// logged and skipped rather than aborting the cycle, for the reason key rotation gives:
// a malformed mandate must not be able to stall the chain.
//
// The caller must hold e.mu.
func (e *Engine) processMandateEntriesLocked(entries []chain.ProvenanceEntry) {
	for _, pe := range entries {
		if pe.Label != chain.MandateLabel {
			continue
		}

		body, ok := e.mandateBodies[pe.Hash]
		if !ok {
			log.Printf("IPC: mandate %x anchored without a known body, ignoring", pe.Hash)
			continue
		}

		lookup := func(rootID [16]byte) ([]byte, bool) { return e.mandateAuthorityLookupLocked(rootID) }
		if err := validation.ValidateMandateAuthority(body, lookup); err != nil {
			log.Printf("IPC: rejecting anchored mandate %x: %v", body.ID, err)
			continue
		}

		if err := e.mandateResolver.Put(body); err != nil {
			log.Printf("IPC: rejecting anchored mandate %x: %v", body.ID, err)
			continue
		}
		log.Printf("IPC: mandate %x anchored (authority=%x version=%d rules=%d)",
			body.ID, body.Authority, body.Version, len(body.Rules))
	}
}

// validateEntryAgainstMandatesLocked applies the mandates in force to one entry.
//
// An entry that references no mandate makes no claim and is accepted: most entries in a
// provenance chain are governed by nothing, and rejecting them would make the mandate
// mechanism unusable. An entry that does reference one is held to the rules of the
// mandate it names.
//
// The caller must hold e.mu.
func (e *Engine) validateEntryAgainstMandatesLocked(entry *chain.ProvenanceEntry) error {
	return e.mandateValidator.ValidateEntryAgainstMandates(entry, entry.Timestamp)
}
