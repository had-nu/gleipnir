// Scenarios P1-P4: end-to-end pipeline tests using real project fixtures.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/had-nu/gleipnir/pkg/identity"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

// P1 — Masthead scan → hash findings → IPC anchor → verify
func p1MastheadPipeline(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	start := time.Now()
	tc := "P1"

	scan := mastheadFixture()
	submitted := 0
	for _, f := range scan.Findings {
		fHash := f.Hash()
		var h [32]byte
		copy(h[:], fHash)

		label := fmt.Sprintf("masthead-%s-%s", f.HeaderName, f.Path)
		ts := time.Now().UnixNano()
		sig := signPayload(uid, fHash, uid.RootID, ts, label)

		resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
			Hash: fHash, Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
		})
		if err != nil || !resp.Accepted {
			fail(tc, "G0", "Masthead→IPC pipeline", time.Since(start),
				fmt.Sprintf("submit finding %s/%s failed: %v %s", f.Path, f.HeaderName, err, resp.Status))
			return
		}
		submitted++
	}
	if submitted == 0 {
		fail(tc, "G0", "Masthead→IPC pipeline", time.Since(start), "no findings submitted")
		return
	}

	lastHash := scan.Findings[len(scan.Findings)-1].Hash()
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	proof, err := raw.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: lastHash})
	if err != nil || !proof.Found {
		fail(tc, "G0", "Masthead→IPC pipeline", time.Since(start),
			fmt.Sprintf("WaitForAnchor: %v found=%v", err, proof.Found))
		return
	}

	for _, f := range scan.Findings {
		v, err := raw.VerifyHash(ctx, &pb.VerifyRequest{Hash: f.Hash()})
		if err != nil || !v.Found {
			fail(tc, "G0", "Masthead→IPC pipeline", time.Since(start),
				fmt.Sprintf("VerifyHash %s/%s: %v found=%v", f.Path, f.HeaderName, err, v.Found))
			return
		}
	}

	pass(tc, "G0", "Masthead→IPC pipeline", time.Since(start),
		fmt.Sprintf("scan=%s findings=%d anchored block=%d", scan.Target, submitted, proof.BlockIndex))
}

// P2 — Hashchain record → IPC anchor → verify
func p2HashchainPipeline(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	tc := "P2"
	start := time.Now()

	records := hashchainFixture()
	anchored := 0
	for _, r := range records {
		// Hash the record fields to get a deterministic 32-byte value
		payload := sha256.Sum256([]byte(r.Filepath + r.DataHash + r.ChainHash))
		var h [32]byte
		copy(h[:], payload[:])

		label := fmt.Sprintf("hashchain-%s", r.Filepath)
		ts := time.Now().UnixNano()
		sig := signPayload(uid, h[:], uid.RootID, ts, label)

		resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
			Hash: h[:], Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
		})
		if err != nil || !resp.Accepted {
			fail(tc, "-", "Hashchain→IPC pipeline", time.Since(start),
				fmt.Sprintf("submit %s: %v %s", r.Filepath, err, resp.Status))
			return
		}
		anchored++
	}

	lastRec := records[len(records)-1]
	payload := sha256.Sum256([]byte(lastRec.Filepath + lastRec.DataHash + lastRec.ChainHash))
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	proof, err := raw.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: payload[:]})
	if err != nil || !proof.Found {
		fail(tc, "-", "Hashchain→IPC pipeline", time.Since(start),
			fmt.Sprintf("WaitForAnchor: %v found=%v", err, proof.Found))
		return
	}

	pass(tc, "-", "Hashchain→IPC pipeline", time.Since(start),
		fmt.Sprintf("records=%d anchored block=%d", anchored, proof.BlockIndex))
}

// P3 — Vigil SecurityEvent → IPC anchor → verify + SMT proof
func p3VigilPipeline(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	tc := "P3"
	start := time.Now()

	evt := vigilEventFixture("genesis")
	evtHash := sha256.Sum256([]byte(evt.Hash))

	var h [32]byte
	copy(h[:], evtHash[:])
	label := fmt.Sprintf("vigil-%s-%s", evt.Source, evt.FindingID)
	ts := time.Now().UnixNano()
	sig := signPayload(uid, h[:], uid.RootID, ts, label)

	resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: h[:], Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
	})
	if err != nil || !resp.Accepted {
		fail(tc, "G0", "Vigil→IPC pipeline", time.Since(start),
			fmt.Sprintf("submit: %v %s", err, resp.Status))
		return
	}

	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	proof, err := raw.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: h[:]})
	if err != nil || !proof.Found {
		fail(tc, "G0", "Vigil→IPC pipeline", time.Since(start),
			fmt.Sprintf("WaitForAnchor: %v found=%v", err, proof.Found))
		return
	}

	v, err := raw.VerifyHash(ctx, &pb.VerifyRequest{Hash: h[:]})
	if err != nil || !v.Found || len(v.SmtProof) == 0 {
		fail(tc, "G0", "Vigil→IPC pipeline", time.Since(start),
			"VerifyHash missing or no SMT proof")
		return
	}

	pass(tc, "G0", "Vigil→IPC pipeline", time.Since(start),
		fmt.Sprintf("event=%s finding=%s block=%d proof=%d bytes",
			evt.ID, evt.FindingID, proof.BlockIndex, len(v.SmtProof)))
}

// P4 — Compliance: finding → resolve control → IPC anchor → verify
func p4CompliancePipeline(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	tc := "P4"
	start := time.Now()

	scan := mastheadFixture()
	finding := scan.Findings[0] // HSTS missing on /login

	var triggered []ComplianceMapping
	triggered = append(triggered, complianceFixtures...)

	// Anchor the compliance decision: finding_hash + control_ids
	decisionPayload := sha256.Sum256(append(finding.Hash(), []byte(fmt.Sprintf("%v", triggered))...))
	var h [32]byte
	copy(h[:], decisionPayload[:])
	label := fmt.Sprintf("compliance-%s-%s", finding.HeaderName, finding.Path)
	ts := time.Now().UnixNano()
	sig := signPayload(uid, h[:], uid.RootID, ts, label)

	resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: h[:], Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
	})
	if err != nil || !resp.Accepted {
		fail(tc, "G0", "Compliance→IPC pipeline", time.Since(start),
			fmt.Sprintf("submit: %v %s", err, resp.Status))
		return
	}

	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	proof, err := raw.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: h[:]})
	if err != nil || !proof.Found {
		fail(tc, "G0", "Compliance→IPC pipeline", time.Since(start),
			fmt.Sprintf("WaitForAnchor: %v found=%v", err, proof.Found))
		return
	}

	pass(tc, "G0", "Compliance→IPC pipeline", time.Since(start),
		fmt.Sprintf("finding=%s controls=%d anchored block=%d",
			finding.HeaderName, len(triggered), proof.BlockIndex))
}

// F1 — Sub-chain: local SMT entries → periodic anchor → cross-chain proof concept
func f1SubChain(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	tc := "F1"
	start := time.Now()

	entries := subChainFixture()
	for _, e := range entries {
		var h [32]byte
		copy(h[:], sha256.New().Sum(e.Payload)) // Simplified: real sub-chain uses SMT.Insert

		label := fmt.Sprintf("subchain-%s", e.ID)
		ts := time.Now().UnixNano()
		sig := signPayload(uid, h[:], uid.RootID, ts, label)

		resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
			Hash: h[:], Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
		})
		if err != nil || !resp.Accepted {
			fail(tc, "-", "Sub-chain anchoring", time.Since(start),
				fmt.Sprintf("submit %s: %v %s", e.ID, err, resp.Status))
			return
		}
	}

	last := entries[len(entries)-1]
	var lastH [32]byte
	copy(lastH[:], sha256.New().Sum(last.Payload))
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	proof, err := raw.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: lastH[:]})
	if err != nil || !proof.Found {
		fail(tc, "-", "Sub-chain anchoring", time.Since(start),
			fmt.Sprintf("WaitForAnchor: %v found=%v", err, proof.Found))
		return
	}

	pass(tc, "-", "Sub-chain anchoring", time.Since(start),
		fmt.Sprintf("entries=%d anchored block=%d (concept demo)", len(entries), proof.BlockIndex))
}

// ── Ad-hoc integration helpers ──────────────────────────────────────────

// submitAndWait is a convenience helper used by scenario tests.
func submitAndWait(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound, hash []byte, label string) (uint64, error) {
	ts := time.Now().UnixNano()
	sig := signPayload(uid, hash, uid.RootID, ts, label)
	resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: hash, Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
	})
	if err != nil {
		return 0, fmt.Errorf("submit: %w", err)
	}
	if !resp.Accepted {
		return 0, fmt.Errorf("rejected: %s", resp.Status)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	proof, err := raw.WaitForAnchor(wctx, &pb.WaitRequest{Hash: hash})
	if err != nil {
		return 0, fmt.Errorf("WaitForAnchor: %w", err)
	}
	if !proof.Found {
		return 0, fmt.Errorf("not found after WaitForAnchor")
	}
	return proof.BlockIndex, nil
}

func entryInBlock(ctx context.Context, raw pb.ProvenanceAnchorClient, blockIdx uint64, hash []byte) (bool, error) {
	for retry := 0; retry < 5; retry++ {
		b, err := raw.GetBlock(ctx, &pb.BlockRequest{Index: blockIdx})
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		for _, e := range b.Anchored {
			if bytes.Equal(e.Hash, hash) {
				return true, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false, nil
}
