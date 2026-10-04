//nolint:errcheck // test assertions
package server

import (
	"context"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
	"github.com/had-nu/gleipnir/pkg/state"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rotationFixture holds the incoming key material a client would generate for itself,
// mirroring a validator whose new key lives outside the node (HSM/KMS).
type rotationFixture struct {
	newPK  [chain.KeyRotationPublicKeySize]byte
	newVRF [chain.KeyRotationVRFKeySize]byte
	newSK  []byte
	rootID [16]byte
	effect uint64
	expiry uint64
	sigNew []byte
}

func newRotationFixture(t *testing.T, srv *Server) *rotationFixture {
	t.Helper()

	pk, sk, err := identity.GenerateDilithiumKeyFromSeed(rotationSeed(7))
	if err != nil {
		t.Fatalf("generate incoming key: %v", err)
	}

	var vrf [chain.KeyRotationVRFKeySize]byte
	copy(vrf[:], rotationSeed(8))

	lead := state.DefaultConfig.KeyRotationLeadTime
	overlap := state.DefaultConfig.MinKeyOverlap
	effective := srv.Engine().Cycle() + lead
	expiry := effective + overlap

	rootID := srv.Engine().NodeUID().RootID

	// The client signs the canonical payload with the incoming key: rule 2.
	payload, err := chain.KeyRotationPayloadFor(rootID, pk, vrf, effective, expiry)
	if err != nil {
		t.Fatalf("KeyRotationPayloadFor: %v", err)
	}

	return &rotationFixture{
		newPK:  pk,
		newVRF: vrf,
		newSK:  sk,
		rootID: rootID,
		effect: effective,
		expiry: expiry,
		sigNew: identity.SignDilithium(sk, payload),
	}
}

func rotationSeed(n byte) []byte {
	s := make([]byte, identity.Dilithium3SeedSize)
	for i := range s {
		s[i] = n + byte(i)
	}
	return s
}

func (f *rotationFixture) request() *pb.KeyRotationRequest {
	return &pb.KeyRotationRequest{
		NewDilithiumPublicKey: f.newPK[:],
		NewVrfPublicKey:       f.newVRF[:],
		EffectiveCycle:        f.effect,
		ExpiryCycle:           f.expiry,
		SignatureNew:          f.sigNew,
	}
}

// A well-formed rotation is accepted and enqueued; both signatures verify.
func TestGrpcSubmitKeyRotation(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newRotationFixture(t, srv)
	resp, err := client.SubmitKeyRotation(ctx, f.request())
	if err != nil {
		t.Fatalf("SubmitKeyRotation: %v", err)
	}
	if resp.Status != "pending" {
		t.Fatalf("status = %q, want pending (error: %s)", resp.Status, resp.Error)
	}
	if len(resp.EntryHash) != 32 {
		t.Fatalf("entry hash must be 32 bytes, got %d", len(resp.EntryHash))
	}

	// The node's outgoing signature (rule 1) plus the client's incoming signature
	// (rule 2) must together validate.
	var hash [32]byte
	copy(hash[:], resp.EntryHash)
	body, ok := srv.Engine().RotationBody(hash)
	if !ok {
		t.Fatal("engine must retain the rotation body")
	}
	if !body.VerifyHash() {
		t.Fatal("rotation body hash must commit to its contents")
	}
	if err := srv.Engine().KeyRotationValidator().Validate(body); err != nil {
		t.Fatalf("assembled rotation must satisfy all five rules: %v", err)
	}
	if srv.Engine().PendingCount() == 0 {
		t.Fatal("rotation must be enqueued for anchoring")
	}
}

// Malformed requests are rejected at the transport layer with InvalidArgument.
func TestGrpcSubmitKeyRotationValidatesSizes(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	base := newRotationFixture(t, srv).request()

	cases := []struct {
		name   string
		mutate func(*pb.KeyRotationRequest)
	}{
		{"short public key", func(r *pb.KeyRotationRequest) { r.NewDilithiumPublicKey = r.NewDilithiumPublicKey[:100] }},
		{"short vrf key", func(r *pb.KeyRotationRequest) { r.NewVrfPublicKey = r.NewVrfPublicKey[:8] }},
		{"missing signature_new", func(r *pb.KeyRotationRequest) { r.SignatureNew = nil }},
		{"short signature_new", func(r *pb.KeyRotationRequest) { r.SignatureNew = r.SignatureNew[:64] }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pb.KeyRotationRequest{
				NewDilithiumPublicKey: append([]byte(nil), base.NewDilithiumPublicKey...),
				NewVrfPublicKey:       append([]byte(nil), base.NewVrfPublicKey...),
				EffectiveCycle:        base.EffectiveCycle,
				ExpiryCycle:           base.ExpiryCycle,
				SignatureNew:          append([]byte(nil), base.SignatureNew...),
			}
			tc.mutate(req)

			_, err := client.SubmitKeyRotation(ctx, req)
			if err == nil {
				t.Fatal("expected an error for a malformed request")
			}
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err: %v)", got, err)
			}
		})
	}
}

// A rotation that breaks the protocol rules is reported as "rejected" with a reason,
// not as a transport error, and is not enqueued.
func TestGrpcSubmitKeyRotationRejectsRuleViolations(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("EarlyEffectiveCycle", func(t *testing.T) {
		f := newRotationFixture(t, srv)
		req := f.request()
		req.EffectiveCycle = 1 // far inside the lead-time window
		req.ExpiryCycle = 1000

		before := srv.Engine().PendingCount()
		resp, err := client.SubmitKeyRotation(ctx, req)
		if err != nil {
			t.Fatalf("rule violations must be reported in the response, got transport error: %v", err)
		}
		if resp.Status != "rejected" {
			t.Fatalf("status = %q, want rejected", resp.Status)
		}
		if resp.Error == "" {
			t.Fatal("rejected response must explain why")
		}
		if got := srv.Engine().PendingCount(); got != before {
			t.Fatalf("rejected rotation must not be enqueued: %d -> %d", before, got)
		}
	})

	t.Run("InsufficientOverlap", func(t *testing.T) {
		f := newRotationFixture(t, srv)
		req := f.request()
		req.ExpiryCycle = req.EffectiveCycle + 1 // below MinKeyOverlap

		resp, err := client.SubmitKeyRotation(ctx, req)
		if err != nil {
			t.Fatalf("rule violations must be reported in the response: %v", err)
		}
		if resp.Status != "rejected" {
			t.Fatalf("status = %q, want rejected", resp.Status)
		}
	})

	// A signature by the wrong key cannot satisfy rule 2.
	t.Run("ForgedSignatureNew", func(t *testing.T) {
		f := newRotationFixture(t, srv)
		req := f.request()

		_, otherSK, err := identity.GenerateDilithiumKeyFromSeed(rotationSeed(99))
		if err != nil {
			t.Fatalf("generate other key: %v", err)
		}
		payload, err := chain.KeyRotationPayloadFor(f.rootID, f.newPK, f.newVRF, f.effect, f.expiry)
		if err != nil {
			t.Fatalf("KeyRotationPayloadFor: %v", err)
		}
		req.SignatureNew = identity.SignDilithium(otherSK, payload)

		resp, err := client.SubmitKeyRotation(ctx, req)
		if err != nil {
			t.Fatalf("rule violations must be reported in the response: %v", err)
		}
		if resp.Status != "rejected" {
			t.Fatalf("status = %q, want rejected for a forged signature", resp.Status)
		}
	})

	// A correctly sized but random signature is likewise rejected.
	t.Run("RandomSignatureNew", func(t *testing.T) {
		f := newRotationFixture(t, srv)
		req := f.request()
		req.SignatureNew = make([]byte, chain.KeyRotationSignatureSize)

		resp, err := client.SubmitKeyRotation(ctx, req)
		if err != nil {
			t.Fatalf("rule violations must be reported in the response: %v", err)
		}
		if resp.Status != "rejected" {
			t.Fatalf("status = %q, want rejected for an invalid signature", resp.Status)
		}
	})
}

// GetActivePublicKey reports one key before a rotation and two during its overlap.
func TestGrpcGetActivePublicKey(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newRotationFixture(t, srv)
	nodePK := srv.Engine().NodeUID().PublicKey

	// Before the rotation: only the node's registered key.
	resp, err := client.GetActivePublicKey(ctx, &pb.ActiveKeyRequest{Cycle: 0})
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(resp.PublicKeys) != 1 {
		t.Fatalf("before rotation want 1 active key, got %d", len(resp.PublicKeys))
	}
	if resp.InOverlap {
		t.Fatal("must not report overlap before any rotation")
	}
	if string(resp.PublicKeys[0]) != string(nodePK[:]) {
		t.Fatal("before rotation the registered key must be active")
	}

	// Anchor the rotation so the engine learns the new key.
	if _, err := client.SubmitKeyRotation(ctx, f.request()); err != nil {
		t.Fatalf("SubmitKeyRotation: %v", err)
	}
	srv.Engine().RunCycle()

	// During overlap: both keys, outgoing first.
	mid, err := client.GetActivePublicKey(ctx, &pb.ActiveKeyRequest{Cycle: f.effect})
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(mid.PublicKeys) != 2 || !mid.InOverlap {
		t.Fatalf("during overlap want 2 active keys, got %d (overlap=%v)", len(mid.PublicKeys), mid.InOverlap)
	}
	if string(mid.PublicKeys[0]) != string(nodePK[:]) {
		t.Fatal("overlap: first key must be the outgoing key")
	}
	if string(mid.PublicKeys[1]) != string(f.newPK[:]) {
		t.Fatal("overlap: second key must be the incoming key")
	}

	// After the overlap closes: only the incoming key.
	after, err := client.GetActivePublicKey(ctx, &pb.ActiveKeyRequest{Cycle: f.expiry + 1})
	if err != nil {
		t.Fatalf("GetActivePublicKey: %v", err)
	}
	if len(after.PublicKeys) != 1 || after.InOverlap {
		t.Fatalf("after overlap want 1 active key, got %d (overlap=%v)", len(after.PublicKeys), after.InOverlap)
	}
	if string(after.PublicKeys[0]) != string(f.newPK[:]) {
		t.Fatal("after overlap the incoming key must be the only active key")
	}
}

// GetActivePublicKey validates the validator id and reports unknown validators.
func TestGrpcGetActivePublicKeyValidation(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("BadValidatorIDLength", func(t *testing.T) {
		_, err := client.GetActivePublicKey(ctx, &pb.ActiveKeyRequest{ValidatorId: []byte{1, 2, 3}})
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", got)
		}
	})

	t.Run("UnknownValidator", func(t *testing.T) {
		unknown := make([]byte, 16)
		copy(unknown, []byte("nobody-here"))
		_, err := client.GetActivePublicKey(ctx, &pb.ActiveKeyRequest{ValidatorId: unknown, Cycle: 1})
		if got := status.Code(err); got != codes.NotFound {
			t.Fatalf("code = %v, want NotFound", got)
		}
	})
}
