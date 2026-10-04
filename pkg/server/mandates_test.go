// Mandate compliance endpoint tests — 3CP v2.0 §13.
//
//nolint:errcheck // test assertions
package server

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"

	pb "github.com/had-nu/gleipnir/pkg/server/pb"
)

// signedMandate builds a mandate signed by the server's own validator key, which is the
// identity registered in its validator set and therefore resolvable as an authority.
func signedMandate(t *testing.T, srv *Server, mutate func(*chain.MandateEntry)) []byte {
	t.Helper()

	m := &chain.MandateEntry{
		Authority:  srv.identity.RootID,
		Version:    1,
		ValidFrom:  time.Now().Add(-time.Hour).UnixNano(),
		ValidUntil: time.Now().Add(time.Hour).UnixNano(),
		Rules: []chain.Rule{{
			EventClass:     "3cp:consensus-config",
			RequiredFields: []string{"Signature"},
			Mandatory:      true,
		}},
	}
	if mutate != nil {
		mutate(m)
	}
	if err := m.SignWithAuthority(srv.identity.SecretKey); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}
	encoded, err := chain.MarshalMandateEntry(m)
	if err != nil {
		t.Fatalf("MarshalMandateEntry: %v", err)
	}
	return encoded
}

// TestSubmitMandateOverGRPC is the happy path end to end.
func TestSubmitMandateOverGRPC(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx := context.Background()
	encoded := signedMandate(t, srv, nil)

	resp, err := client.SubmitMandate(ctx, &pb.MandateRequest{Mandate: encoded})
	if err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}
	if len(resp.MandateId) != 32 {
		t.Fatalf("got a %d-byte mandate_id, want 32", len(resp.MandateId))
	}
	if resp.Version != 1 {
		t.Errorf("got version %d, want 1", resp.Version)
	}

	// And it must be retrievable by the identifier the response handed back.
	got, err := client.GetMandate(ctx, &pb.GetMandateRequest{MandateId: resp.MandateId})
	if err != nil {
		t.Fatalf("GetMandate: %v", err)
	}
	roundTripped, err := chain.UnmarshalMandateEntry(got.Mandate)
	if err != nil {
		t.Fatalf("UnmarshalMandateEntry: %v", err)
	}
	if len(roundTripped.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(roundTripped.Rules))
	}

	active, err := client.GetActiveMandates(ctx, &pb.GetActiveMandatesRequest{})
	if err != nil {
		t.Fatalf("GetActiveMandates: %v", err)
	}
	if len(active.Mandates) != 1 {
		t.Errorf("got %d active mandates, want 1", len(active.Mandates))
	}
}

// TestSubmitMandateRejectsUnsigned is the endpoint-level security property: a caller
// cannot install policy in another node's name through the gRPC surface.
func TestSubmitMandateRejectsUnsigned(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	// Sign, then strip the signature and restamp the identifier so the only thing wrong
	// with the body is the missing signature.
	encoded := signedMandate(t, srv, nil)
	body, err := chain.UnmarshalMandateEntry(encoded)
	if err != nil {
		t.Fatalf("UnmarshalMandateEntry: %v", err)
	}
	body.Signature = nil
	body.ID = body.MandateID()
	unsigned, err := chain.MarshalMandateEntry(body)
	if err != nil {
		t.Fatalf("MarshalMandateEntry: %v", err)
	}

	_, err = client.SubmitMandate(context.Background(), &pb.MandateRequest{Mandate: unsigned})
	if err == nil {
		t.Fatal("an unsigned mandate was accepted over gRPC")
	}
	if code := status.Code(err); code != codes.PermissionDenied {
		t.Errorf("got code %v, want PermissionDenied", code)
	}

	// And nothing was installed.
	active, err := client.GetActiveMandates(context.Background(), &pb.GetActiveMandatesRequest{})
	if err != nil {
		t.Fatalf("GetActiveMandates: %v", err)
	}
	if len(active.Mandates) != 0 {
		t.Errorf("the rejected mandate is active anyway: %d entries", len(active.Mandates))
	}
}

// TestSubmitMandateRejectsTamperedBody covers a body whose rules were relaxed after
// signing while keeping the original identifier.
//
// The expected code is InvalidArgument, not PermissionDenied. The identifier no longer
// commits to the contents, so the encoding is self-inconsistent: that is malformed
// client data. PermissionDenied is reserved for a body that is well-formed and
// internally consistent but not authorised, such as one signed by the wrong key.
func TestSubmitMandateRejectsTamperedBody(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	encoded := signedMandate(t, srv, nil)
	body, err := chain.UnmarshalMandateEntry(encoded)
	if err != nil {
		t.Fatalf("UnmarshalMandateEntry: %v", err)
	}
	body.Rules = []chain.Rule{{EventClass: "3cp:anything", Mandatory: false}}
	tampered, err := chain.MarshalMandateEntry(body)
	if err != nil {
		t.Fatalf("MarshalMandateEntry: %v", err)
	}

	_, err = client.SubmitMandate(context.Background(), &pb.MandateRequest{Mandate: tampered})
	if err == nil {
		t.Fatal("a mandate with relaxed rules was accepted under its original identifier")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("got code %v, want InvalidArgument", code)
	}

	active, err := client.GetActiveMandates(context.Background(), &pb.GetActiveMandatesRequest{})
	if err != nil {
		t.Fatalf("GetActiveMandates: %v", err)
	}
	if len(active.Mandates) != 0 {
		t.Errorf("the rejected mandate is active anyway: %d entries", len(active.Mandates))
	}
}

// TestSubmitMandateRejectsMalformed checks the input is validated before it is treated
// as a mandate at all.
func TestSubmitMandateRejectsMalformed(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	_, err := client.SubmitMandate(context.Background(), &pb.MandateRequest{Mandate: []byte("not a mandate")})
	if err == nil {
		t.Fatal("malformed mandate bytes were accepted")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("got code %v, want InvalidArgument", code)
	}
}

// TestGetMandateRejectsBadIdentifier checks the length is validated rather than
// silently zero-padding a short identifier into a lookup for the wrong mandate.
func TestGetMandateRejectsBadIdentifier(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	_, err := client.GetMandate(context.Background(), &pb.GetMandateRequest{MandateId: []byte{1, 2, 3}})
	if err == nil {
		t.Fatal("a 3-byte mandate_id was accepted")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("got code %v, want InvalidArgument", code)
	}
}

// TestGetMandateNotFound checks a well-formed but unknown identifier is a NotFound
// rather than an empty response that reads as a mandate with no rules.
func TestGetMandateNotFound(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	_, err := client.GetMandate(context.Background(), &pb.GetMandateRequest{MandateId: make([]byte, 32)})
	if err == nil {
		t.Fatal("an unknown mandate_id returned a response")
	}
	if code := status.Code(err); code != codes.NotFound {
		t.Errorf("got code %v, want NotFound", code)
	}
}

// TestCheckComplianceOverGRPC exercises the auditor's query: a mandatory obligation with
// no matching anchored entry must come back as a gap, not as an empty all-clear.
func TestCheckComplianceOverGRPC(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx := context.Background()
	encoded := signedMandate(t, srv, nil)
	submitted, err := client.SubmitMandate(ctx, &pb.MandateRequest{Mandate: encoded})
	if err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}

	now := time.Now()
	report, err := client.CheckCompliance(ctx, &pb.ComplianceCheckRequest{
		MandateId:      submitted.MandateId,
		StartTimestamp: now.Add(-time.Hour).UnixNano(),
		EndTimestamp:   now.UnixNano(),
	})
	if err != nil {
		t.Fatalf("CheckCompliance: %v", err)
	}
	if report.TotalExpected == 0 {
		t.Fatal("no obligations were expected")
	}
	if report.TotalAnchored != 0 {
		t.Errorf("got %d anchored, want 0", report.TotalAnchored)
	}
	if len(report.Gaps) == 0 {
		t.Fatal("an unhonoured mandate reported no gaps")
	}
	if report.ComplianceRate != 0 {
		t.Errorf("compliance rate is %v, want 0", report.ComplianceRate)
	}

	gap := report.Gaps[0]
	if gap.EventClass != "3cp:consensus-config" {
		t.Errorf("gap event class is %q, want %q", gap.EventClass, "3cp:consensus-config")
	}
	if gap.Status != "missing" {
		t.Errorf("gap status is %q, want %q", gap.Status, "missing")
	}
	if len(gap.MandateId) != 32 {
		t.Errorf("gap mandate_id is %d bytes, want 32", len(gap.MandateId))
	}
}

// TestCheckComplianceRejectsBadInput covers the identifier length and the window.
func TestCheckComplianceRejectsBadInput(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	_, err := client.CheckCompliance(ctx, &pb.ComplianceCheckRequest{MandateId: []byte{1}})
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("short mandate_id: got code %v, want InvalidArgument", code)
	}

	now := time.Now()
	_, err = client.CheckCompliance(ctx, &pb.ComplianceCheckRequest{
		MandateId:      make([]byte, 32),
		StartTimestamp: now.UnixNano(),
		EndTimestamp:   now.Add(-time.Hour).UnixNano(),
	})
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("inverted window: got code %v, want InvalidArgument", code)
	}

	_, err = client.CheckCompliance(ctx, &pb.ComplianceCheckRequest{
		MandateId: make([]byte, 32),
	})
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("zero timestamps: got code %v, want InvalidArgument", code)
	}
}

// TestCheckComplianceUnknownMandate checks a valid window against an unknown mandate.
func TestCheckComplianceUnknownMandate(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	now := time.Now()
	_, err := client.CheckCompliance(context.Background(), &pb.ComplianceCheckRequest{
		MandateId:      make([]byte, 32),
		StartTimestamp: now.Add(-time.Hour).UnixNano(),
		EndTimestamp:   now.UnixNano(),
	})
	if err == nil {
		t.Fatal("checking an unknown mandate succeeded")
	}
	if code := status.Code(err); code != codes.NotFound {
		t.Errorf("got code %v, want NotFound", code)
	}
}

// TestGetActiveMandatesEmptyIsNotAnError checks a chain with no mandates reports an empty
// list rather than an error, since that is the normal state of a fresh network.
func TestGetActiveMandatesEmptyIsNotAnError(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := client.GetActiveMandates(context.Background(), &pb.GetActiveMandatesRequest{})
	if err != nil {
		t.Fatalf("GetActiveMandates on an empty resolver: %v", err)
	}
	if len(resp.Mandates) != 0 {
		t.Errorf("got %d mandates, want 0", len(resp.Mandates))
	}
}

// TestGetActiveMandatesHonoursWindow checks the timestamp actually filters: a mandate
// that has not started yet must not be reported as active.
func TestGetActiveMandatesHonoursWindow(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	// Valid only in a year.
	future := time.Now().Add(365 * 24 * time.Hour).UnixNano()
	encoded := signedMandate(t, srv, func(m *chain.MandateEntry) {
		m.ValidFrom = future
		m.ValidUntil = future + 3600
	})
	if _, err := client.SubmitMandate(ctx, &pb.MandateRequest{Mandate: encoded}); err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}

	resp, err := client.GetActiveMandates(ctx, &pb.GetActiveMandatesRequest{})
	if err != nil {
		t.Fatalf("GetActiveMandates: %v", err)
	}
	if len(resp.Mandates) != 0 {
		t.Errorf("a mandate valid in a year was reported active now: %d entries", len(resp.Mandates))
	}

	later, err := client.GetActiveMandates(ctx, &pb.GetActiveMandatesRequest{Timestamp: future + 60})
	if err != nil {
		t.Fatalf("GetActiveMandates: %v", err)
	}
	if len(later.Mandates) != 1 {
		t.Errorf("the mandate was not active inside its own validity window: %d entries", len(later.Mandates))
	}
}

// TestMandateRoundTripPreservesRules checks the CBOR a client receives decodes to the
// rules it submitted, so an auditor reading the chain sees what was actually mandated.
func TestMandateRoundTripPreservesRules(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()
	ctx := context.Background()

	encoded := signedMandate(t, srv, func(m *chain.MandateEntry) {
		m.PolicyURI = []byte("https://example.invalid/policy")
		m.Rules[0].Description = "consensus changes must be signed"
		m.Rules[0].RequiredFields = []string{"Signature", "Reference", "Approver"}
		m.Rules[0].MaxDeferralSec = 86400
		m.Rules[0].SeverityMax = 0.9
	})
	submitted, err := client.SubmitMandate(ctx, &pb.MandateRequest{Mandate: encoded})
	if err != nil {
		t.Fatalf("SubmitMandate: %v", err)
	}

	got, err := client.GetMandate(ctx, &pb.GetMandateRequest{MandateId: submitted.MandateId})
	if err != nil {
		t.Fatalf("GetMandate: %v", err)
	}
	body, err := chain.UnmarshalMandateEntry(got.Mandate)
	if err != nil {
		t.Fatalf("UnmarshalMandateEntry: %v", err)
	}
	if string(body.PolicyURI) != "https://example.invalid/policy" {
		t.Errorf("policy URI is %q, want the submitted document", body.PolicyURI)
	}
	rule := body.Rules[0]
	if len(rule.RequiredFields) != 3 {
		t.Errorf("got %d required fields, want 3", len(rule.RequiredFields))
	}
	if rule.MaxDeferralSec != 86400 {
		t.Errorf("MaxDeferralSec is %d, want 86400", rule.MaxDeferralSec)
	}
	if !body.VerifyHash() {
		t.Error("the returned body does not verify against its own identifier")
	}
	if !body.VerifyAuthoritySignature(srv.identity.PublicKey[:]) {
		t.Error("the returned body does not carry a signature from its named authority")
	}
}

// TestSubmitMandateFromForeignAuthority checks the lookup really does consult registered
// keys, rather than accepting a well-signed mandate from an unknown issuer.
func TestSubmitMandateFromForeignAuthority(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	_, foreignSK, err := identity.GenerateDilithiumKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	m := &chain.MandateEntry{
		Authority:  srv.identity.RootID, // claims the server's own identity
		ValidFrom:  time.Now().UnixNano(),
		ValidUntil: time.Now().Add(time.Hour).UnixNano(),
		Rules:      []chain.Rule{{EventClass: "3cp:x", Mandatory: true}},
	}
	if err := m.SignWithAuthority(foreignSK); err != nil {
		t.Fatalf("SignWithAuthority: %v", err)
	}
	encoded, err := chain.MarshalMandateEntry(m)
	if err != nil {
		t.Fatalf("MarshalMandateEntry: %v", err)
	}

	if _, err := client.SubmitMandate(context.Background(), &pb.MandateRequest{Mandate: encoded}); err == nil {
		t.Fatal("a mandate signed by an unregistered key in the server's name was accepted")
	}
}
