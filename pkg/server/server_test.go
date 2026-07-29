//nolint:errcheck // test assertions
package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/had-nu/gleipnir/pkg/identity"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func bufDialer(lis *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, url string) (net.Conn, error) {
		return lis.Dial()
	}
}

func newTestServer(t *testing.T) (*Server, pb.ProvenanceAnchorClient, func()) {
	var networkID [32]byte
	copy(networkID[:], []byte("test-network-id"))
	uid, err := identity.NewUIDZero("test-server", networkID, true)
	if err != nil {
		t.Fatalf("NewUIDZero error: %v", err)
	}
	srv := NewServer("test-node", uid)

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	pb.RegisterProvenanceAnchorServer(gs, srv)

	go gs.Serve(lis)

	conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer(lis)))
	if err != nil {
		t.Fatal(err)
	}

	client := pb.NewProvenanceAnchorClient(conn)

	return srv, client, func() {
		gs.Stop()
		lis.Close()
		conn.Close()
		srv.Stop()
	}
}

func signSubmitRequest(uid *identity.UIDZeroSoulbound, hash []byte, submitter []byte, ts int64, label string) []byte {
	tsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBytes, uint64(ts))
	signed := make([]byte, 0, len(hash)+len(submitter)+len(tsBytes)+len(label))
	signed = append(signed, hash...)
	signed = append(signed, submitter...)
	signed = append(signed, tsBytes...)
	signed = append(signed, label...)
	return identity.SignDilithium(uid.SecretKey, signed)
}

func TestGrpcSubmitHashRejectsUnauthenticated(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))
	ts := time.Now().UnixNano()
	var submitter [16]byte
	copy(submitter[:], []byte("unknown"))

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: submitter[:],
		Timestamp: ts,
		Label:     "test",
		Signature: make([]byte, 2700), // invalid signature
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted {
		t.Fatal("unauthenticated submit should be rejected")
	}
}

func TestGrpcSubmitHashRejectsBadSignature(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("test-network-id"))
	uid, _ := identity.NewUIDZero("test-client", networkID, true)
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))
	ts := time.Now().UnixNano()
	wrongUID, _ := identity.NewUIDZero("wrong-key", networkID, true)

	var uidSubmitter, wrongSubmitter [16]byte
	copy(uidSubmitter[:], uid.RootID[:])
	copy(wrongSubmitter[:], wrongUID.RootID[:])

	sig := signSubmitRequest(wrongUID, hash[:], uidSubmitter[:], ts, "test")

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: uidSubmitter[:],
		Timestamp: ts,
		Label:     "test",
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted {
		t.Fatal("submit with bad signature should be rejected")
	}
}

func TestGrpcSubmitHashSubmitterMismatch(t *testing.T) {
	var networkID [32]byte
	copy(networkID[:], []byte("test-network-id"))
	clientUID, _ := identity.NewUIDZero("test-client", networkID, true)
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))
	ts := time.Now().UnixNano()
	var submitter [16]byte
	copy(submitter[:], clientUID.RootID[:])

	sig := signSubmitRequest(clientUID, hash[:], submitter[:], ts, "test")

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: submitter[:],
		Timestamp: ts,
		Label:     "test",
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted {
		t.Fatal("submit from unknown identity should be rejected as submitter mismatch")
	}
}

func TestGrpcSubmitHashAuthenticated(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	// Use the server's own identity which is already registered in srv.keys
	var uid *identity.UIDZeroSoulbound
	for _, v := range srv.keys {
		uid = v
		break
	}
	if uid == nil {
		t.Fatal("server has no registered identity")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))
	ts := time.Now().UnixNano()
	var submitter [16]byte
	copy(submitter[:], uid.RootID[:])

	sig := signSubmitRequest(uid, hash[:], submitter[:], ts, "test")

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: submitter[:],
		Timestamp: ts,
		Label:     "test",
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Accepted {
		t.Fatalf("submit rejected: %s", resp.Status)
	}

	// Wait for anchor
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	proof, err := client.WaitForAnchor(ctx2, &pb.WaitRequest{Hash: hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Found {
		t.Fatal("anchor not found after submit")
	}
	t.Logf("Anchor found at block %d", proof.BlockIndex)
}

func TestGrpcVerifyHash(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	// Use server's identity
	var uid *identity.UIDZeroSoulbound
	for _, v := range srv.keys {
		uid = v
		break
	}
	if uid == nil {
		t.Fatal("server has no registered identity")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("verify-test-entry"))
	ts := time.Now().UnixNano()
	var submitter [16]byte
	copy(submitter[:], uid.RootID[:])

	sig := signSubmitRequest(uid, hash[:], submitter[:], ts, "verify-test")

	// Submit
	_, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: submitter[:],
		Timestamp: ts,
		Label:     "verify-test",
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for anchor
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	proof, err := client.WaitForAnchor(ctx2, &pb.WaitRequest{Hash: hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Found {
		t.Fatal("anchor not found")
	}

	// Now verify
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	verifyResp, err := client.VerifyHash(ctx3, &pb.VerifyRequest{Hash: hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResp.Found {
		t.Fatal("verify should find anchored hash")
	}
	if verifyResp.BlockIndex != proof.BlockIndex {
		t.Fatalf("block index mismatch: verify=%d wait=%d", verifyResp.BlockIndex, proof.BlockIndex)
	}
}

func TestGrpcGetHealth(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetHealth(ctx, &pb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.BlockHeight < 0 {
		t.Fatalf("invalid block height: %d", resp.BlockHeight)
	}
	if len(resp.CurrentRoot) != 32 {
		t.Fatalf("invalid root length: %d", len(resp.CurrentRoot))
	}
}

func TestGrpcGetCurrentStateRoot(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCurrentStateRoot(ctx, &pb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.StateRoot) != 32 {
		t.Fatalf("invalid state root length: %d", len(resp.StateRoot))
	}
}

func TestGrpcGetBlock(t *testing.T) {
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	var uid *identity.UIDZeroSoulbound
	for _, v := range srv.keys {
		uid = v
		break
	}
	if uid == nil {
		t.Fatal("server has no registered identity")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("block-test"))
	ts := time.Now().UnixNano()
	var submitter [16]byte
	copy(submitter[:], uid.RootID[:])

	sig := signSubmitRequest(uid, hash[:], submitter[:], ts, "block-test")

	_, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: submitter[:],
		Timestamp: ts,
		Label:     "block-test",
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	proof, err := client.WaitForAnchor(ctx2, &pb.WaitRequest{Hash: hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Found {
		t.Fatal("anchor not found")
	}

	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	block, err := client.GetBlock(ctx3, &pb.BlockRequest{Index: proof.BlockIndex})
	if err != nil {
		t.Fatal(err)
	}
	if block.Index != proof.BlockIndex {
		t.Fatalf("block index mismatch: got %d expected %d", block.Index, proof.BlockIndex)
	}
	if len(block.Anchored) == 0 {
		t.Fatal("block should have anchored entries")
	}
}