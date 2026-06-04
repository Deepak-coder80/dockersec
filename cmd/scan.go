package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/report"
	"github.com/Deepak-coder80/dockersec/internal/rules"
	"github.com/spf13/cobra"

	_ "github.com/Deepak-coder80/dockersec/internal/rules/dockerfile"
)

var outputFormat string

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a Dockerfile or docker-compose file",
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	// register the --format flag with "text" as default
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text or table")
}

func runScan(cmd *cobra.Command, args []string) {
	path := args[0]
	dockerfilePath := filepath.Join(path, "Dockerfile")

	parsed, err := parser.ParseDockerfile(dockerfilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading Dockerfile: %s\n", err)
		os.Exit(1)
	}

	findings := rules.RunDockerfileRules(parsed)

	switch outputFormat {
	case "table":
		report.PrintTable(findings)
	default:
		report.PrintFindings(findings)
	}
}
