// IPC Protocol Conformance Test
// Test cases derived from PROTOCOL.md v1 — each case maps to a protocol requirement.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/smt"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
	"github.com/had-nu/gleipnir/pkg/validation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	smtDepth    = 256
	labelPrefix = "conf-"
)

type TestResult struct {
	Name    string
	TC      string
	Gap     string
	Passed  bool
	Detail  string
	Latency time.Duration
}

var results []TestResult

func pass(tc, gap, name string, latency time.Duration, detail string) {
	results = append(results, TestResult{Name: name, TC: tc, Gap: gap, Passed: true, Detail: detail, Latency: latency})
}

func fail(tc, gap, name string, latency time.Duration, detail string) {
	results = append(results, TestResult{Name: name, TC: tc, Gap: gap, Passed: false, Detail: detail, Latency: latency})
}

func main() {
	target := flag.String("target", "val-1:50051", "gRPC target address")
	uidFile := flag.String("uid-file", "/uids/uid-1.cbor", "path to validator UID0 CBOR file")
	timeout := flag.Duration("timeout", 120*time.Second, "total test suite timeout")
	flag.Parse()

	fmt.Println("=== IPC Protocol Conformance Test ===")
	fmt.Printf("Target: %s\n", *target)
	fmt.Printf("UID:    %s\n", *uidFile)
	fmt.Printf("PROTOCOL.md v1 — Gaps G1–G5\n\n")

	uidData, err := os.ReadFile(*uidFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: read UID file: %v\n", err)
		os.Exit(1)
	}
	uid, err := identity.UnmarshalCBOR(uidData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: unmarshal UID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Validator identity: %s\n\n", uid.ID())

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: dial %s: %v\n", *target, err)
		os.Exit(1)
	}
	defer conn.Close()
	raw := pb.NewProvenanceAnchorClient(conn)

	waitForReady(ctx, raw)

	// ── G3 Auth & Validation (existing) ──
	tc01SubmitValid(ctx, raw, uid)
	tc02NoSignature(ctx, raw, uid)
	tc03BadSignature(ctx, raw, uid)
	tc04UnknownSubmitter(ctx, raw)
	tc05ZeroHash(ctx, raw, uid)

	// ── G4 Lifecycle (existing) ──
	tc06FullLifecycle(ctx, raw, uid)

	// ── Basic protocol (existing) ──
	tc07VerifyNonexistent(ctx, raw)
	tc08Health(ctx, raw)
	tc09StateRoot(ctx, raw)
	tc10GetBlock(ctx, raw)

	// ── G1+G2 Approver+Reference (existing) ──
	tc11ApproverReference(ctx, raw, uid)

	// ── G5 Timeout (existing) ──
	tc12WaitTimeout(ctx, raw)

	// ── Category A: Extended Validation ──
	a1WrongLengthHash(ctx, raw, uid)
	a2LabelEdgeCases(ctx, raw, uid)
	a4EntryNonRepudiation(ctx, raw, uid)
	a6DedupAfterAnchor(ctx, raw, uid)
	a8WaitAlreadyAnchored(ctx, raw, uid)
	a9VerifyBeforeAnchor(ctx, raw, uid)

	// ── Category B: Chain Integrity ──
	b1PrevHashChain(ctx, raw, uid)
	b5QuorumSigs(ctx, raw, uid)

	// ── Category C: Cryptographic Proofs ──
	c2SmtProofVsBlockRoot(ctx, raw, uid)
	c3DecisionChain(ctx, raw, uid)
	c5EntrySigVerify(ctx, raw, uid)

	// ── Category D: Error Handling ──
	d1StreamBlocks(ctx, raw, uid)
	d3EmptySubmit(ctx, raw, uid)
	d4LargePayload(ctx, raw, uid)

	// ── Category E: Observability ──
	e1LambdaNonNegative(ctx, raw, uid)
	e3StateRootChanges(ctx, raw, uid)

	// ── Pipeline Scenarios (real-project fixtures) ──
	// Note: P1-P4 produce additional blocks used by chain integrity tests above.
	p1MastheadPipeline(ctx, raw, uid)
	p2HashchainPipeline(ctx, raw, uid)
	p3VigilPipeline(ctx, raw, uid)
	p4CompliancePipeline(ctx, raw, uid)
	f1SubChain(ctx, raw, uid)

	fmt.Println()
	printReport()
	fmt.Println()

	if !allPassed() {
		os.Exit(1)
	}
}

func waitForReady(ctx context.Context, raw pb.ProvenanceAnchorClient) {
	fmt.Print("Waiting for validators to be ready... ")
	for {
		select {
		case <-ctx.Done():
			fmt.Println("TIMEOUT")
			return
		default:
		}
		hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
		resp, err := raw.GetHealth(hctx, &pb.Empty{})
		hcancel()
		if err == nil && resp.Status == "running" {
			fmt.Printf("OK (node=%s height=%d peers=%d/%d)\n\n",
				resp.NodeId, resp.BlockHeight, resp.ActivePeers, resp.TotalPeers)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func allPassed() bool {
	for _, r := range results {
		if !r.Passed {
			return false
		}
	}
	return true
}

func printReport() {
	var passed, failed int
	var totalLatency time.Duration
	fmt.Printf("%-6s %-5s %-34s %-6s  %s\n", "TC", "Gap", "Name", "Result", "Latency")
	fmt.Println("------ ------ ---------------------------------- ------  -------")
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
			failed++
		} else {
			passed++
		}
		totalLatency += r.Latency
		fmt.Printf("%-6s %-5s %-34s %-6s  %v\n", r.TC, r.Gap, r.Name, status, r.Latency.Round(time.Millisecond))
	}
	fmt.Println("------ ------ ---------------------------------- ------  -------")
	fmt.Printf("Passed: %d / %d", passed, len(results))
	if failed > 0 {
		fmt.Printf("  FAILED: %d", failed)
	}
	fmt.Println()
	fmt.Printf("Total time: %v\n", totalLatency.Round(time.Millisecond))
	fmt.Println()

	if failed > 0 {
		fmt.Println("Failures:")
		for _, r := range results {
			if !r.Passed {
				fmt.Printf("  %s (%s): %s\n", r.TC, r.Name, r.Detail)
			}
		}
		fmt.Println()
	}
}

func randomHash() []byte {
	h := make([]byte, 32)
	rand.Read(h)
	return h
}

func signPayload(uid *identity.UIDZeroSoulbound, hash, submitter []byte, ts int64, label string) []byte {
	tsLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsLE, uint64(ts))
	signed := make([]byte, 0, len(hash)+len(submitter)+len(tsLE)+len(label))
	signed = append(signed, hash...)
	signed = append(signed, submitter...)
	signed = append(signed, tsLE...)
	signed = append(signed, label...)
	return identity.SignDilithium(uid.SecretKey, signed)
}

// TC01 — G3: SubmitHash with valid Dilithium3 signature → accepted
func tc01SubmitValid(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	hash := randomHash()
	ts := time.Now().UnixNano()
	label := labelPrefix + "tc01"
	sig := signPayload(uid, hash, uid.RootID, ts, label)

	start := time.Now()
	resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: hash, Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
	})
	latency := time.Since(start)

	if err != nil {
		fail("TC01", "G3", "SubmitHash authenticated", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if !resp.Accepted {
		fail("TC01", "G3", "SubmitHash authenticated", latency, fmt.Sprintf("rejected: %s (code=%s)", resp.Status, resp.ErrorCode))
		return
	}
	pass("TC01", "G3", "SubmitHash authenticated", latency, resp.Status)
}

// TC02 — G3: SubmitHash without signature → INVALID_SIGNATURE
func tc02NoSignature(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	hash := randomHash()
	ts := time.Now().UnixNano()
	label := labelPrefix + "tc02"

	start := time.Now()
	resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: hash, Submitter: uid.RootID, Timestamp: ts, Label: label,
	})
	latency := time.Since(start)

	if err != nil {
		fail("TC02", "G3", "SubmitHash no signature", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if resp.Accepted {
		fail("TC02", "G3", "SubmitHash no signature", latency, "accepted without signature")
		return
	}
	if resp.ErrorCode != "INVALID_SIGNATURE" {
		fail("TC02", "G3", "SubmitHash no signature", latency, fmt.Sprintf("expected INVALID_SIGNATURE, got %s", resp.ErrorCode))
		return
	}
	pass("TC02", "G3", "SubmitHash no signature", latency, resp.ErrorCode)
}

// TC03 — G3: SubmitHash with forged signature → INVALID_SIGNATURE
func tc03BadSignature(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	hash := randomHash()
	ts := time.Now().UnixNano()
	label := labelPrefix + "tc03"

	start := time.Now()
	resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: hash, Submitter: uid.RootID, Timestamp: ts, Label: label,
		Signature: bytes.Repeat([]byte{0x42}, 2700),
	})
	latency := time.Since(start)

	if err != nil {
		fail("TC03", "G3", "SubmitHash bad signature", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if resp.Accepted {
		fail("TC03", "G3", "SubmitHash bad signature", latency, "accepted with forged signature")
		return
	}
	if resp.ErrorCode != validation.ErrCodeInvalidSignature {
		fail("TC03", "G3", "SubmitHash bad signature", latency, fmt.Sprintf("expected %s, got %s", validation.ErrCodeInvalidSignature, resp.ErrorCode))
		return
	}
	pass("TC03", "G3", "SubmitHash bad signature", latency, resp.ErrorCode)
}

// TC04 — G3: SubmitHash with unregistered submitter → SUBMITTER_MISMATCH
func tc04UnknownSubmitter(ctx context.Context, raw pb.ProvenanceAnchorClient) {
	unknownID := make([]byte, 16)
	rand.Read(unknownID)
	hash := randomHash()
	ts := time.Now().UnixNano()
	label := labelPrefix + "tc04"

	start := time.Now()
	resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: hash, Submitter: unknownID, Timestamp: ts, Label: label,
	})
	latency := time.Since(start)

	if err != nil {
		fail("TC04", "G3", "SubmitHash unknown submitter", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if resp.Accepted {
		fail("TC04", "G3", "SubmitHash unknown submitter", latency, "accepted with unknown submitter")
		return
	}
	if resp.ErrorCode != validation.ErrCodeSubmitterMismatch {
		fail("TC04", "G3", "SubmitHash unknown submitter", latency, fmt.Sprintf("expected %s, got %s", validation.ErrCodeSubmitterMismatch, resp.ErrorCode))
		return
	}
	pass("TC04", "G3", "SubmitHash unknown submitter", latency, resp.ErrorCode)
}

// TC05 — protocol: SubmitHash with all-zero hash → INVALID_HASH
func tc05ZeroHash(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	zeroHash := make([]byte, 32)
	ts := time.Now().UnixNano()
	label := labelPrefix + "tc05"
	sig := signPayload(uid, zeroHash, uid.RootID, ts, label)

	start := time.Now()
	resp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: zeroHash, Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
	})
	latency := time.Since(start)

	if err != nil {
		fail("TC05", "-", "Zero hash rejected", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if resp.Accepted {
		fail("TC05", "-", "Zero hash rejected", latency, "zero hash was accepted")
		return
	}
	if resp.ErrorCode != validation.ErrCodeInvalidHash {
		fail("TC05", "-", "Zero hash rejected", latency, fmt.Sprintf("expected %s, got %s", validation.ErrCodeInvalidHash, resp.ErrorCode))
		return
	}
	pass("TC05", "-", "Zero hash rejected", latency, resp.ErrorCode)
}

// TC06 — G4: Submit → WaitForAnchor → VerifyHash → SMT proof verifies
func tc06FullLifecycle(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	hash := randomHash()
	ts := time.Now().UnixNano()
	label := labelPrefix + "tc06"
	sig := signPayload(uid, hash, uid.RootID, ts, label)

	start := time.Now()
	submitResp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: hash, Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
	})
	if err != nil {
		fail("TC06", "G4", "Submit→Wait→Verify", time.Since(start), fmt.Sprintf("submit gRPC error: %v", err))
		return
	}
	if !submitResp.Accepted {
		fail("TC06", "G4", "Submit→Wait→Verify", time.Since(start), fmt.Sprintf("submit rejected: %s", submitResp.Status))
		return
	}

	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	proof, err := raw.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: hash})
	if err != nil {
		fail("TC06", "G4", "Submit→Wait→Verify", time.Since(start), fmt.Sprintf("WaitForAnchor error: %v", err))
		return
	}
	if !proof.Found {
		fail("TC06", "G4", "Submit→Wait→Verify", time.Since(start), "proof not found after WaitForAnchor")
		return
	}

	verifyResp, err := raw.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash})
	if err != nil {
		fail("TC06", "G4", "Submit→Wait→Verify", time.Since(start), fmt.Sprintf("VerifyHash error: %v", err))
		return
	}
	if !verifyResp.Found {
		fail("TC06", "G4", "Submit→Wait→Verify", time.Since(start), "VerifyHash returned not found")
		return
	}

	if len(verifyResp.SmtProof) == 0 {
		fail("TC06", "G4", "Submit→Wait→Verify", time.Since(start), "empty SMT proof")
		return
	}

	var root [32]byte
	copy(root[:], verifyResp.StateRoot)
	var hashArr [32]byte
	copy(hashArr[:], hash)

	var siblings [][32]byte
	for i := 0; i+32 <= len(verifyResp.SmtProof); i += 32 {
		var sib [32]byte
		copy(sib[:], verifyResp.SmtProof[i:i+32])
		siblings = append(siblings, sib)
	}

	tree := smt.New(smtDepth)
	if !tree.Verify(hashArr[:], hashArr[:], root, siblings) {
		fail("TC06", "G4", "Submit→Wait→Verify", time.Since(start), "SMT proof verification against state root FAILED")
		return
	}

	latency := time.Since(start)
	pass("TC06", "G4", "Submit→Wait→Verify", latency,
		fmt.Sprintf("block=%d root=%s", proof.BlockIndex, hex.EncodeToString(proof.StateRoot[:8])))
}

// TC07 — protocol: VerifyHash with nonexistent hash → Found=false
func tc07VerifyNonexistent(ctx context.Context, raw pb.ProvenanceAnchorClient) {
	hash := randomHash()

	start := time.Now()
	resp, err := raw.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash})
	latency := time.Since(start)

	if err != nil {
		fail("TC07", "-", "VerifyHash nonexistent", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if resp.Found {
		fail("TC07", "-", "VerifyHash nonexistent", latency, "returned Found=true for nonexistent hash")
		return
	}
	pass("TC07", "-", "VerifyHash nonexistent", latency, "Found=false")
}

// TC08 — protocol: GetHealth returns running status
func tc08Health(ctx context.Context, raw pb.ProvenanceAnchorClient) {
	start := time.Now()
	resp, err := raw.GetHealth(ctx, &pb.Empty{})
	latency := time.Since(start)

	if err != nil {
		fail("TC08", "-", "GetHealth", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if resp.Status != "running" {
		fail("TC08", "-", "GetHealth", latency, fmt.Sprintf("status=%s", resp.Status))
		return
	}
	pass("TC08", "-", "GetHealth", latency, fmt.Sprintf("height=%d peers=%d/%d λ₁=%.2f",
		resp.BlockHeight, resp.ActivePeers, resp.TotalPeers, resp.Lambda1))
}

// TC09 — protocol: GetCurrentStateRoot returns non-nil root
func tc09StateRoot(ctx context.Context, raw pb.ProvenanceAnchorClient) {
	start := time.Now()
	resp, err := raw.GetCurrentStateRoot(ctx, &pb.Empty{})
	latency := time.Since(start)

	if err != nil {
		fail("TC09", "-", "GetCurrentStateRoot", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if len(resp.StateRoot) != 32 {
		fail("TC09", "-", "GetCurrentStateRoot", latency, fmt.Sprintf("state root length=%d (expected 32)", len(resp.StateRoot)))
		return
	}
	pass("TC09", "-", "GetCurrentStateRoot", latency, fmt.Sprintf("block=%d root=%s", resp.BlockIndex, hex.EncodeToString(resp.StateRoot[:8])))
}

// TC10 — protocol: GetBlock(0) returns a valid block
func tc10GetBlock(ctx context.Context, raw pb.ProvenanceAnchorClient) {
	start := time.Now()
	resp, err := raw.GetBlock(ctx, &pb.BlockRequest{Index: 0})
	latency := time.Since(start)

	if err != nil {
		fail("TC10", "-", "GetBlock(0)", latency, fmt.Sprintf("gRPC error: %v", err))
		return
	}
	if len(resp.StateRoot) == 0 {
		fail("TC10", "-", "GetBlock(0)", latency, "empty block (genesis not found)")
		return
	}

	detail := fmt.Sprintf("index=%d entries=%d proposer=%s",
		resp.Index, len(resp.Anchored), hex.EncodeToString(resp.Proposer[:8]))
	if len(resp.Anchored) > 0 {
		detail += fmt.Sprintf(" sigs=%d", len(resp.Sigs))
	}
	pass("TC10", "-", "GetBlock(0)", latency, detail)
}

// TC11 — G1+G2: Submit with approver + reference → retained in proof
func tc11ApproverReference(ctx context.Context, raw pb.ProvenanceAnchorClient, uid *identity.UIDZeroSoulbound) {
	hash := randomHash()
	ts := time.Now().UnixNano()
	label := labelPrefix + "tc11"
	approver := []byte("approver-test-42")
	reference := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	sig := signPayload(uid, hash, uid.RootID, ts, label)

	start := time.Now()
	submitResp, err := raw.SubmitHash(ctx, &pb.SubmitRequest{
		Hash: hash, Submitter: uid.RootID, Timestamp: ts, Label: label, Signature: sig,
		Approver: approver, Reference: reference,
	})
	if err != nil {
		fail("TC11", "G1+G2", "Approver+Reference", time.Since(start), fmt.Sprintf("submit error: %v", err))
		return
	}
	if !submitResp.Accepted {
		fail("TC11", "G1+G2", "Approver+Reference", time.Since(start), fmt.Sprintf("rejected: %s", submitResp.Status))
		return
	}

	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	proof, err := raw.WaitForAnchor(waitCtx, &pb.WaitRequest{Hash: hash})
	if err != nil {
		fail("TC11", "G1+G2", "Approver+Reference", time.Since(start), fmt.Sprintf("WaitForAnchor error: %v", err))
		return
	}
	if !proof.Found {
		fail("TC11", "G1+G2", "Approver+Reference", time.Since(start), "proof not found")
		return
	}

	verifyResp, err := raw.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash})
	if err != nil {
		fail("TC11", "G1+G2", "Approver+Reference", time.Since(start), fmt.Sprintf("VerifyHash error: %v", err))
		return
	}

	gaps := ""
	if len(verifyResp.Submitter) > 0 {
		gaps = "Submitter"
	}
	if len(proof.SmtProof) > 0 {
		if gaps != "" {
			gaps += "+"
		}
		gaps += "SMTProof"
	}

	var foundEntry bool
	for retry := 0; retry < 5; retry++ {
		blockResp, err := raw.GetBlock(ctx, &pb.BlockRequest{Index: proof.BlockIndex})
		if err != nil {
			if retry == 4 {
				fail("TC11", "G1+G2", "Approver+Reference", time.Since(start), fmt.Sprintf("GetBlock error: %v", err))
				return
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}

		for _, e := range blockResp.Anchored {
			if bytes.Equal(e.Hash, hash) {
				foundEntry = true

				if len(e.Approver) == 0 {
					gaps = "G1(approver missing)"
				} else if !bytes.Equal(e.Approver, approver) {
					gaps = fmt.Sprintf("G1(approver mismatch: %x != %x)", e.Approver, approver)
				} else if len(e.Reference) == 0 {
					gaps = "G2(reference missing)"
				} else if !bytes.Equal(e.Reference, reference) {
					gaps = fmt.Sprintf("G2(reference mismatch: %x != %x)", e.Reference, reference)
				} else {
					gaps = ""
				}
				break
			}
		}
		if foundEntry {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !foundEntry {
		fail("TC11", "G1+G2", "Approver+Reference", time.Since(start), "entry not found in block after retries")
		return
	}

	if len(gaps) > 0 {
		fail("TC11", "G1+G2", "Approver+Reference", time.Since(start), gaps)
		return
	}

	latency := time.Since(start)
	pass("TC11", "G1+G2", "Approver+Reference", latency,
		fmt.Sprintf("block=%d entry has approver+reference", proof.BlockIndex))
}

// TC12 — G5: WaitForAnchor with short context → fail-closed (error, not panic)
func tc12WaitTimeout(ctx context.Context, raw pb.ProvenanceAnchorClient) {
	hash := randomHash()
	giveUp, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	start := time.Now()
	proof, err := raw.WaitForAnchor(giveUp, &pb.WaitRequest{Hash: hash})
	latency := time.Since(start)

	if err == nil {
		fail("TC12", "G5", "WaitForAnchor timeout", latency,
			fmt.Sprintf("returned proof (Found=%v) instead of error", proof.Found))
		return
	}

	pass("TC12", "G5", "WaitForAnchor timeout", latency, fmt.Sprintf("error: %v", err))
}
