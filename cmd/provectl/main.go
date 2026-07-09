package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/had-nu/prana-provenance-chain/pkg/server/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var addr string

var rootCmd = &cobra.Command{
	Use:   "provectl",
	Short: "IPC (Immutable Provenance Chain) admin CLI — Prana reference implementation",
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate genesis uID0 identities for validators",
	Run: func(cmd *cobra.Command, _ []string) {
		n, _ := cmd.Flags().GetInt("validators")
		out, _ := cmd.Flags().GetString("out")
		if err := cmdInit(n, out); err != nil {
			log.Fatalf("init failed: %v", err)
		}
	},
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Get node health status",
	Run: func(_ *cobra.Command, _ []string) {
		conn := dial()
		defer conn.Close()
		client := pb.NewProvenanceAnchorClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.GetHealth(ctx, &pb.Empty{})
		if err != nil {
			log.Fatalf("health failed: %v", err)
		}
		fmt.Printf("Node:       %s\n", resp.NodeId)
		fmt.Printf("Status:     %s\n", resp.Status)
		fmt.Printf("Height:     %d\n", resp.BlockHeight)
		fmt.Printf("StateRoot:  %x\n", resp.CurrentRoot)
		fmt.Printf("λ₁:         %.4f\n", resp.Lambda1)
		fmt.Printf("Peers:      %d/%d\n", resp.ActivePeers, resp.TotalPeers)
		fmt.Printf("Pending:    %d\n", resp.PendingHashes)
		fmt.Printf("TPS:        %.2f\n", resp.AvgTps)
	},
}

var rootStateCmd = &cobra.Command{
	Use:   "root",
	Short: "Get current state root",
	Run: func(_ *cobra.Command, _ []string) {
		conn := dial()
		defer conn.Close()
		client := pb.NewProvenanceAnchorClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.GetCurrentStateRoot(ctx, &pb.Empty{})
		if err != nil {
			log.Fatalf("root failed: %v", err)
		}
		fmt.Printf("StateRoot:  %x\n", resp.StateRoot)
		fmt.Printf("Block:      %d\n", resp.BlockIndex)
		fmt.Printf("λ₁:         %.4f\n", resp.Lambda1)
	},
}

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submit a hash for anchoring",
	Run: func(cmd *cobra.Command, _ []string) {
		hashHex, _ := cmd.Flags().GetString("hash")
		label, _ := cmd.Flags().GetString("label")
		if hashHex == "" {
			log.Fatal("--hash is required")
		}

		hash, err := hex.DecodeString(hashHex)
		if err != nil {
			log.Fatalf("invalid hash: %v", err)
		}

		conn := dial()
		defer conn.Close()
		client := pb.NewProvenanceAnchorClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		resp, err := client.SubmitHash(ctx, &pb.SubmitRequest{
			Hash:      hash,
			Label:     label,
			Timestamp: time.Now().UnixNano(),
		})
		if err != nil {
			log.Fatalf("submit failed: %v", err)
		}
		fmt.Printf("Accepted:   %v\n", resp.Accepted)
		fmt.Printf("Status:     %s\n", resp.Status)
		fmt.Printf("Block:      %d\n", resp.BlockIndex)
		fmt.Printf("BlockTime:  %d\n", resp.BlockTime)
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an anchored hash",
	Run: func(cmd *cobra.Command, _ []string) {
		hashHex, _ := cmd.Flags().GetString("hash")
		if hashHex == "" {
			log.Fatal("--hash is required")
		}

		hash, err := hex.DecodeString(hashHex)
		if err != nil {
			log.Fatalf("invalid hash: %v", err)
		}

		conn := dial()
		defer conn.Close()
		client := pb.NewProvenanceAnchorClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.VerifyHash(ctx, &pb.VerifyRequest{Hash: hash})
		if err != nil {
			log.Fatalf("verify failed: %v", err)
		}
		if resp.Found {
			fmt.Printf("Found:       yes\n")
			fmt.Printf("Block:       %d\n", resp.BlockIndex)
			fmt.Printf("BlockTime:   %d\n", resp.BlockTime)
			fmt.Printf("StateRoot:   %x\n", resp.StateRoot)
			fmt.Printf("Submitter:   %x\n", resp.Submitter)
			fmt.Printf("Label:       %s\n", resp.Label)
		} else {
			fmt.Printf("Found:       no\n")
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&addr, "addr", "a", "localhost:50051", "gRPC server address")

	initCmd.Flags().IntP("validators", "n", 5, "Number of validator identities to generate")
	initCmd.Flags().StringP("out", "o", "/tmp/uids", "Output directory for uID0 CBOR files")

	submitCmd.Flags().String("hash", "", "Hash to submit (hex)")
	submitCmd.Flags().String("label", "", "Label for the submission")

	verifyCmd.Flags().String("hash", "", "Hash to verify (hex)")

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(rootStateCmd)
	rootCmd.AddCommand(submitCmd)
	rootCmd.AddCommand(verifyCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func dial() *grpc.ClientConn {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	return conn
}
