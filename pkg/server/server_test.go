//nolint:errcheck // test assertions
package server

import (
	"context"
	"crypto/rand"
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
	uid := identity.NewUIDZero("test-server", true)
	srv := NewServer("test-node", uid)

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	pb.RegisterProvenanceAnchorServer(gs, srv)

	go gs.Serve(lis)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(bufDialer(lis)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}

	client := pb.NewProvenanceAnchorClient(conn)

	cleanup := func() {
		conn.Close()
		gs.Stop()
		srv.Stop()
	}

	return srv, client, cleanup
}

func signSubmitRequest(uid *identity.UIDZeroSoulbound, hash, submitter []byte, ts int64, label string) []byte {
	tsLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsLE, uint64(ts))
	signed := make([]byte, 0, len(hash)+len(submitter)+len(tsLE)+len(label))
	signed = append(signed, hash...)
	signed = append(signed, submitter...)
	signed = append(signed, tsLE...)
	signed = append(signed, label...)
	return identity.SignDilithium(uid.SecretKey, signed)
}

func TestServerHealth(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetHealth(ctx, &pb.Empty{})
	if err != nil {
		t.Fatal(err)
	}

	if resp.NodeId != "test-node" {
		t.Fatalf("expected test-node, got %s", resp.NodeId)
	}
	if resp.Status != "running" {
		t.Fatalf("expected running, got %s", resp.Status)
	}
}

func TestServerSubmitAndVerify(t *testing.T) {
	uid := identity.NewUIDZero("test-server", true)
	srv, client, cleanup := newTestServer(t)
	defer cleanup()

	srv.keys[uid.ID()] = uid

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))
	ts := time.Now().UnixNano()
	sig := signSubmitRequest(uid, hash[:], uid.RootID, ts, "test")

	submitResp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: uid.RootID,
		Label:     "test",
		Timestamp: ts,
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !submitResp.Accepted {
		t.Fatalf("submit should be accepted, got: %s", submitResp.Status)
	}

	time.Sleep(4 * time.Second)

	verifyResp, err := client.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResp.Found {
		t.Fatal("hash should be found after cycle")
	}
	if verifyResp.Label != "test" {
		t.Fatalf("expected label test, got %s", verifyResp.Label)
	}
}

func TestServerStateRoot(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCurrentStateRoot(ctx, &pb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
}

func TestServerVerifyNotFound(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := make([]byte, 32)
	rand.Read(hash)

	resp, err := client.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Found {
		t.Fatal("random hash should not be found")
	}
}

func TestGrpcSubmitHashRejectsUnauthenticated(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: []byte("unknown-submitter"),
		Timestamp: time.Now().UnixNano(),
		Label:     "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted {
		t.Fatal("unauthenticated submit should be rejected")
	}
}

func TestGrpcSubmitHashRejectsBadSignature(t *testing.T) {
	uid := identity.NewUIDZero("test-client", true)
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))
	ts := time.Now().UnixNano()
	wrongUID := identity.NewUIDZero("wrong-key", true)
	sig := signSubmitRequest(wrongUID, hash[:], uid.RootID, ts, "test")

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: uid.RootID,
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
	clientUID := identity.NewUIDZero("test-client", true)
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))
	ts := time.Now().UnixNano()
	sig := signSubmitRequest(clientUID, hash[:], clientUID.RootID, ts, "test")

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: clientUID.RootID,
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
	sig := signSubmitRequest(uid, hash[:], uid.RootID, ts, "test-auth")

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: uid.RootID,
		Timestamp: ts,
		Label:     "test-auth",
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Accepted {
		t.Fatalf("authenticated submit should be accepted, got: %s", resp.Status)
	}

	time.Sleep(4 * time.Second)

	verifyResp, err := client.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResp.Found {
		t.Fatal("hash should be found after authenticated submit and cycle")
	}
	if verifyResp.Label != "test-auth" {
		t.Fatalf("expected label test-auth, got %s", verifyResp.Label)
	}
}

func TestGrpcSubmitHashWithApproverAndReference(t *testing.T) {
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

	hash := sha256.Sum256([]byte("test-approver-entry"))
	ts := time.Now().UnixNano()
	sig := signSubmitRequest(uid, hash[:], uid.RootID, ts, "test-approver")
	approver := identity.NewUIDZero("approver-uid", true)
	refHash := sha256.Sum256([]byte("related-entry"))

	resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: uid.RootID,
		Timestamp: ts,
		Label:     "test-approver",
		Signature: sig,
		Approver:  approver.RootID,
		Reference: refHash[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Accepted {
		t.Fatalf("authenticated submit with approver should be accepted, got: %s", resp.Status)
	}

	time.Sleep(4 * time.Second)

	verifyResp, err := client.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyResp.Found {
		t.Fatal("hash should be found after authenticated submit with approver")
	}
}

func TestServerGetBlock(t *testing.T) {
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("non-existent block returns empty", func(t *testing.T) {
		resp, err := client.GetBlock(ctx, &pb.BlockRequest{Index: 999})
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("response should not be nil")
		}
	})
}
