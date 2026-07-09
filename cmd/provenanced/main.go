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

	"github.com/had-nu/prana-provenance-chain/pkg/identity"
	"github.com/had-nu/prana-provenance-chain/pkg/server"
	pb "github.com/had-nu/prana-provenance-chain/pkg/server/pb"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	var (
		grpcPort    = flag.String("grpc-port", "50051", "gRPC server port")
		metricsPort = flag.String("metrics-port", "9090", "Prometheus metrics port")
		uidFile     = flag.String("uid-file", "", "Path to uID0 CBOR file")
		nodeID      = flag.String("node-id", "", "Unique node identifier")
	)
	flag.Parse()

	if *uidFile == "" {
		log.Fatalf("--uid-file is required")
	}
	if *nodeID == "" {
		log.Fatalf("--node-id is required")
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
