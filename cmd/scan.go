package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a Docker file or docker-compose file",
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) {
	path := args[0]
	fmt.Printf("Scanning: %s\n", path)
	fmt.Println("No issues fond (Scanner no implemented yet)")
}
