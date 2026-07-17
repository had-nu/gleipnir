//nolint:errcheck // test assertions
package transport

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/had-nu/gleipnir/pkg/identity"
)

func TestSecureConnHandshakeAndExchange(t *testing.T) {
	// Generate Kyber keys for both sides
	pkA, skA, err := identity.KyberGenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pkB, skB, err := identity.KyberGenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	serverDone := make(chan struct{})
	var serverPeer PeerInfo
	var serverErr error

	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		sc, peer, err := ServerHandshake(conn, skB, pkB, "server-node")
		if err != nil {
			serverErr = err
			return
		}
		serverPeer = peer
		defer sc.Close()

		// Read message from client
		msg, err := sc.ReadMessage()
		if err != nil {
			serverErr = err
			return
		}
		if string(msg) != "hello from client" {
			serverErr = errors.New("unexpected message from client")
			return
		}

		// Reply
		if err := sc.WriteMessage([]byte("hello from server")); err != nil {
			serverErr = err
			return
		}
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	sc, clientPeer, err := ClientHandshake(conn, skA, pkA, "client-node")
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	if clientPeer.PeerID != "server-node" {
		t.Fatalf("expected server-node, got %s", clientPeer.PeerID)
	}

	if err := sc.WriteMessage([]byte("hello from client")); err != nil {
		t.Fatal(err)
	}

	msg, err := sc.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, []byte("hello from server")) {
		t.Fatalf("unexpected reply: %s", string(msg))
	}

	<-serverDone
	if serverErr != nil {
		t.Fatal(serverErr)
	}

	t.Logf("Secure handshake OK: client=%s server=%s",
		clientPeer.PeerID, serverPeer.PeerID)
}
