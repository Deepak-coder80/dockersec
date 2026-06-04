package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/report"
	"github.com/Deepak-coder80/dockersec/internal/rules"
	yamlrules "github.com/Deepak-coder80/dockersec/internal/rules/yaml"
	"github.com/spf13/cobra"

	_ "github.com/Deepak-coder80/dockersec/internal/rules/compose"
	_ "github.com/Deepak-coder80/dockersec/internal/rules/dockerfile"
)

var outputFormat string
var failOn string

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a Dockerfile and docker-compose.yml for security issues",
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text or table")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with code 1 if findings at this severity or above exist (CRITICAL, HIGH, MEDIUM, LOW)")
}

func runScan(cmd *cobra.Command, args []string) {
	path := args[0]

	// load YAML rules from built-in rules directory and user-defined rules
	// missing directories are silently skipped
	for _, rulesDir := range []string{"rules/dockerfile", "rules/compose"} {
		if err := yamlrules.LoadRulesFromDir(rulesDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load rules from %s: %s\n", rulesDir, err)
		}
	}

	var allFindings []models.Finding

	dockerfilePath := filepath.Join(path, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); err == nil {
		parsed, err := parser.ParseDockerfile(dockerfilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading Dockerfile: %s\n", err)
			os.Exit(1)
		}
		findings := rules.RunDockerfileRules(parsed)
		for i := range findings {
			findings[i].Source = "Dockerfile"
		}
		allFindings = append(allFindings, findings...)
	}

	composePath := filepath.Join(path, "docker-compose.yml")
	if _, err := os.Stat(composePath); err == nil {
		cf, err := parser.ParseCompose(composePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading docker-compose.yml: %s\n", err)
			os.Exit(1)
		}
		findings := rules.RunComposeRules(cf)
		for i := range findings {
			findings[i].Source = "docker-compose.yml"
		}
		allFindings = append(allFindings, findings...)
	}

	fmt.Println()

	switch outputFormat {
	case "table":
		report.PrintTable(allFindings)
	default:
		report.PrintFindings(allFindings)
	}

	if failOn != "" {
		if shouldFail(allFindings, models.Severity(failOn)) {
			os.Exit(1)
		}
	}
}

func shouldFail(findings []models.Finding, threshold models.Severity) bool {
	order := map[models.Severity]int{
		models.SeverityCritical: 0,
		models.SeverityHigh:     1,
		models.SeverityMedium:   2,
		models.SeverityLow:      3,
	}

	thresholdLevel, ok := order[threshold]
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid severity: %s. Use CRITICAL, HIGH, MEDIUM or LOW\n", threshold)
		os.Exit(1)
	}

	for _, f := range findings {
		if order[f.Severity] <= thresholdLevel {
			return true
		}
	}
	return false
}
