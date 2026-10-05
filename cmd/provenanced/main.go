package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/had-nu/gleipnir/pkg/consensus"
	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/rest"
	"github.com/had-nu/gleipnir/pkg/server"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
	"github.com/had-nu/gleipnir/pkg/transport/p2p"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func envFlag(name, env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	if def != "" {
		return def
	}
	return ""
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parsePeers turns `addr=uid-file,addr=uid-file` into a peer list including self.
//
// Each entry's uid file must decode to a distinct validator identity. An address on
// its own is not enough for the engine to build a validator set, so requiring the
// file is what stops a peer list from being something that parses cleanly and
// carries no authority information.
//
// The returned slice always contains this node first. consensus.NewEngineWithPeers
// builds the graph as a full mesh over the peers it is given, so omitting self would
// drop this node's own edges and its own entry in the validator set.
func parsePeers(spec string, selfUID *identity.UIDZeroSoulbound, selfAddr string) ([]consensus.Peer, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	if selfUID == nil {
		return nil, errors.New("own identity not resolved")
	}

	peers := []consensus.Peer{{UID: *selfUID, Addr: selfAddr, Alive: true}}
	seen := map[string]bool{selfAddr: true}

	for _, entry := range splitList(spec) {
		addr, uidPath, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("entry %q is not addr=uid-file", entry)
		}
		if seen[addr] {
			return nil, fmt.Errorf("address %q listed more than once", addr)
		}
		seen[addr] = true

		data, err := os.ReadFile(uidPath)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", addr, err)
		}
		peerUID, err := identity.UnmarshalCBOR(data)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", addr, err)
		}
		if peerUID.ID() == selfUID.ID() {
			return nil, fmt.Errorf("peer %s resolves to this node's own identity (%s); "+
				"listing yourself twice would double your vote", addr, peerUID.ID())
		}
		peers = append(peers, consensus.Peer{UID: *peerUID, Addr: addr, Alive: true})
	}

	if len(peers) < 2 {
		return nil, errors.New("only one validator in the peer set; pass at least one other " +
			"validator, or omit --peers entirely to run single-node")
	}
	return peers, nil
}

func main() {
	grpcPort := flag.String("grpc-port", envFlag("", "IPC_GRPC_PORT", "50051"), "gRPC server port")
	metricsPort := flag.String("metrics-port", envFlag("", "IPC_METRICS_PORT", "9090"), "Prometheus metrics port")
	uidFile := flag.String("uid-file", envFlag("", "IPC_UID_FILE", ""), "Path to uID0 CBOR file")
	nodeID := flag.String("node-id", envFlag("", "IPC_NODE_ID", ""), "Unique node identifier")
	peers := flag.String("peers", envFlag("", "IPC_PEERS", ""),
		"Comma-separated peers as addr=uid-file. The uid file is required because the engine "+
			"derives the validator set, quorum size and graph edges from each peer's public "+
			"keys, not from its address. Empty means single-node")
	p2pListen := flag.String("p2p-listen", envFlag("", "IPC_P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001"),
		"libp2p multiaddr to listen on")
	p2pBootstrap := flag.String("p2p-bootstrap", envFlag("", "IPC_P2P_BOOTSTRAP", ""),
		"Comma-separated libp2p peer multiaddrs to dial at startup")
	p2pKey := flag.String("p2p-key", envFlag("", "IPC_P2P_KEY", "/data/libp2p.key"),
		"Path to the libp2p private key. Persisted so the node keeps its peer address across restarts")
	p2pNoMDNS := flag.Bool("p2p-no-mdns", envFlag("", "IPC_P2P_NO_MDNS", "") == "true",
		"Disable mDNS peer discovery")

	restListen := flag.String("rest-listen", envFlag("", "IPC_REST_LISTEN", ":8080"), "REST API listen address")
	restTLSCert := flag.String("rest-tls-cert", envFlag("", "IPC_REST_TLS_CERT", ""), "TLS certificate file for REST API")
	restTLSKey := flag.String("rest-tls-key", envFlag("", "IPC_REST_TLS_KEY", ""), "TLS key file for REST API")
	restKeysDir := flag.String("rest-keys-dir", envFlag("", "IPC_REST_KEYS_DIR", ""), "Directory with UID0 key files for REST auth")
	restAllowedRoots := flag.String("rest-allowed-roots", envFlag("", "IPC_REST_ALLOWED_ROOTS", ""), "Comma-separated whitelist of RootIDs")
	restRateLimit := flag.Int("rest-rate-limit", 5000, "Max requests per minute per RootID")
	allowSimulated := flag.Bool("allow-simulated-identities", envFlag("", "IPC_ALLOW_SIMULATED_IDENTITIES", "") == "true",
		"Accept a simulated (test-derived) identity. Required for provectl genesis fixtures; "+
			"a simulated identity is derived from a predictable entropy source and its key is forgeable")
	flag.Parse()

	if *uidFile == "" {
		log.Fatalf("--uid-file (or IPC_UID_FILE) is required")
	}
	if *nodeID == "" {
		log.Fatalf("--node-id (or IPC_NODE_ID) is required")
	}

	data, err := os.ReadFile(*uidFile)
	if err != nil {
		log.Fatalf("read uid file: %v", err)
	}

	uid, err := identity.UnmarshalCBOR(data)
	if err != nil {
		log.Fatalf("unmarshal uid: %v", err)
	}

	log.Printf("IPC node %s loaded uID0: id=%s", *nodeID, uid.ID())

	serverOpts := []server.ServerOption{server.WithAllowSimulatedIdentities(*allowSimulated)}

	if strings.TrimSpace(*peers) != "" {
		peerList, err := parsePeers(*peers, uid, *nodeID)
		if err != nil {
			log.Fatalf("--peers: %v", err)
		}
		bus, err := p2p.NewGossipBus(context.Background(), p2p.Config{
			ListenAddrs:    []string{*p2pListen},
			BootstrapPeers: splitList(*p2pBootstrap),
			EnableMDNS:     !*p2pNoMDNS,
			PrivateKeyFile: *p2pKey,
			NodeID:         *nodeID,
		})
		if err != nil {
			log.Fatalf("p2p: %v", err)
		}
		defer func() { _ = bus.Close() }()

		serverOpts = append(serverOpts, server.WithPeers(peerList), server.WithGossip(bus))
		log.Printf("IPC node %s joined a %d-validator network", *nodeID, len(peerList))
	}

	srv, err := server.NewServer(*nodeID, uid, serverOpts...)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	defer srv.Stop()

	restSrv, err := rest.NewServer(
		srv.Engine(),
		uid,
		rest.WithKeysDir(*restKeysDir),
		rest.WithAllowedRoots(*restAllowedRoots),
		rest.WithRateLimit(*restRateLimit),
		rest.WithAllowSimulatedIdentities(*allowSimulated),
	)
	if err != nil {
		log.Fatalf("rest: %v", err)
	}
	defer func() { _ = restSrv.Stop() }()

	lis, err := net.Listen("tcp", ":"+*grpcPort)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	gs := grpc.NewServer()
	pb.RegisterProvenanceAnchorServer(gs, srv)
	reflection.Register(gs)

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		// Explicit server rather than http.ListenAndServe, which sets no timeouts at all.
		// Without them a client that opens a connection and dribbles headers holds a
		// goroutine indefinitely, so a handful of slow connections exhausts the process.
		metricsSrv := &http.Server{
			Addr:              ":" + *metricsPort,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server: %v", err)
		}
	}()

	go func() {
		if err := restSrv.ListenAndServe(*restListen, *restTLSCert, *restTLSKey); err != nil {
			log.Printf("rest server: %v", err)
		}
	}()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\nShutting down...")
		gs.GracefulStop()
	}()

	log.Printf("IPC gRPC server listening on :%s, metrics on :%s, REST on :%s",
		*grpcPort, *metricsPort, *restListen)
	if err := gs.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
