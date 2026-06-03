package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Deepak-coder80/dockersec/internal/parser"
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

	dockerfilePath := filepath.Join(path, "Dockerfile")

	parsed, err := parser.ParseDockerfile(dockerfilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsed %s\n\n", parsed.Path)
	for _, inst := range parsed.Instructions {
		fmt.Printf("Line %d\t%s\t%s\n", inst.Line, inst.Command, inst.Value)
	}
}
