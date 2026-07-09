package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	var (
		grpcPort = flag.String("grpc-port", "50051", "gRPC server port")
		uidFile  = flag.String("uid-file", "", "Path to uID0 CBOR file")
		peers    = flag.String("peers", "", "Comma-separated list of peer addresses")
		nodeID   = flag.String("node-id", "", "Unique node identifier")
	)
	flag.Parse()

	if *uidFile == "" {
		log.Fatalf("--uid-file is required")
	}
	if *peers == "" {
		log.Fatalf("--peers is required")
	}
	if *nodeID == "" {
		log.Fatalf("--node-id is required")
	}

	log.Printf("Starting provenanced node %s on port %s", *nodeID, *grpcPort)

	lis, err := net.Listen("tcp", ":"+*grpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	reflection.Register(s)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\nShutting down...")
		s.GracefulStop()
	}()

	log.Printf("gRPC server listening on :%s", *grpcPort)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
