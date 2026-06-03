package report

import (
	"fmt"

	"github.com/Deepak-coder80/dockersec/internal/models"
)

var severityOrder = map[models.Severity]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
}

// PrintFindings prints all findings to terminal
func PrintFindings(findings []models.Finding) {
	if len(findings) == 0 {
		fmt.Println("No issues found.")
		return
	}

	counts := map[models.Severity]int{}

	for _, f := range findings {
		counts[f.Severity]++
		fmt.Printf("\n[%s] %s - %s\n", f.Severity, f.RuleID, f.Description)
		fmt.Printf("  Line : %d\n", f.Line)
		fmt.Printf("  Fix  : %s\n", f.Fix)
	}

	fmt.Printf(
		"\nSummary: %d CRITICAL, %d HIGH, %d MEDIUM, %d LOW\n",
		counts[models.SeverityCritical],
		counts[models.SeverityHigh],
		counts[models.SeverityMedium],
		counts[models.SeverityLow],
	)
}

