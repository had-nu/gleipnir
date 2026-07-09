package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/had-nu/gleipnir/pkg/identity"
	"github.com/had-nu/gleipnir/pkg/server"
	pb "github.com/had-nu/gleipnir/pkg/server/pb"
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

func main() {
	grpcPort := flag.String("grpc-port", envFlag("", "IPC_GRPC_PORT", "50051"), "gRPC server port")
	metricsPort := flag.String("metrics-port", envFlag("", "IPC_METRICS_PORT", "9090"), "Prometheus metrics port")
	uidFile := flag.String("uid-file", envFlag("", "IPC_UID_FILE", ""), "Path to uID0 CBOR file")
	nodeID := flag.String("node-id", envFlag("", "IPC_NODE_ID", ""), "Unique node identifier")
	peers := flag.String("peers", envFlag("", "IPC_PEERS", ""), "Comma-separated peer addresses")
	_ = peers
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

	srv := server.NewServer(*nodeID, uid)
	defer srv.Stop()

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
		if err := http.ListenAndServe(":"+*metricsPort, mux); err != nil {
			log.Printf("metrics server: %v", err)
		}
	}()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\nShutting down...")
		gs.GracefulStop()
	}()

	log.Printf("IPC gRPC server listening on :%s, metrics on :%s", *grpcPort, *metricsPort)
	if err := gs.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
