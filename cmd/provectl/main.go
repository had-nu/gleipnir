package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "provectl",
	Short: "Prana Provenance Chain admin CLI",
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate genesis uID0 identities for validators",
	Run: func(cmd *cobra.Command, args []string) {
		n, _ := cmd.Flags().GetInt("validators")
		out, _ := cmd.Flags().GetString("out")
		if err := cmdInit(n, out); err != nil {
			log.Fatalf("init failed: %v", err)
		}
	},
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Interact with a running provenanced node",
}

func init() {
	initCmd.Flags().IntP("validators", "n", 5, "Number of validator identities to generate")
	initCmd.Flags().StringP("out", "o", "/tmp/uids", "Output directory for uID0 CBOR files")
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(clientCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	_ = flag.CommandLine
}
