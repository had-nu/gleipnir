package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	conn, err := grpc.DialContext(context.Background(), "bufnet",
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
	_, client, cleanup := newTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hash := sha256.Sum256([]byte("test-entry"))

	submitResp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
		Hash:      hash[:],
		Submitter: []byte("test-submitter"),
		Label:     "test",
		Timestamp: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !submitResp.Accepted {
		t.Fatal("submit should be accepted")
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
