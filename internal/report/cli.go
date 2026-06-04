package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
)

var severityOrder = map[models.Severity]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
}

func sortFindings(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})
}

func counts(findings []models.Finding) (int, int, int, int) {
	c, h, m, l := 0, 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			c++
		case models.SeverityHigh:
			h++
		case models.SeverityMedium:
			m++
		case models.SeverityLow:
			l++
		}
	}
	return c, h, m, l
}
func groupBySource(findings []models.Finding) map[string][]models.Finding {
	grouped := make(map[string][]models.Finding)
	for _, f := range findings {
		grouped[f.Source] = append(grouped[f.Source], f)
	}
	return grouped
}

func PrintFindings(findings []models.Finding) {
	if len(findings) == 0 {
		fmt.Println("No issues found.")
		return
	}

	grouped := groupBySource(findings)
	sources := []string{"Dockerfile", "docker-compose.yml"}

	for _, source := range sources {
		group, ok := grouped[source]
		if !ok {
			continue
		}

		sortFindings(group)

		fmt.Printf("\n%s\n", strings.Repeat("═", 70))
		fmt.Printf("  %s\n", source)
		fmt.Printf("%s\n", strings.Repeat("═", 70))

		for _, f := range group {
			fmt.Println(strings.Repeat("─", 70))
			fmt.Printf("  %-10s %s\n", "Severity:", f.Severity)
			fmt.Printf("  %-10s %s\n", "Rule:", f.RuleID)
			fmt.Printf("  %-10s %d\n", "Line:", f.Line)
			fmt.Printf("  %-10s\n\n    %s\n", "Issue:", strings.Join(wrapToLines(f.Description, 64), "\n    "))
			fmt.Printf("  %-10s\n\n    %s\n", "Fix:", strings.Join(wrapToLines(f.Fix, 64), "\n    "))
		}

		fmt.Println(strings.Repeat("─", 70))
		c, h, m, l := counts(group)
		fmt.Printf("\n  Summary: %d CRITICAL  %d HIGH  %d MEDIUM  %d LOW\n\n",
			c, h, m, l)
	}
}

func PrintTable(findings []models.Finding) {
	if len(findings) == 0 {
		fmt.Println("No issues found.")
		return
	}

	colRule := 8
	colSev := 10
	colLine := 6
	colDesc := 44
	colFix := 44

	border := fmt.Sprintf("+%s+%s+%s+%s+%s+",
		strings.Repeat("─", colRule+2),
		strings.Repeat("─", colSev+2),
		strings.Repeat("─", colLine+2),
		strings.Repeat("─", colDesc+2),
		strings.Repeat("─", colFix+2),
	)

	header := fmt.Sprintf("| %-*s | %-*s | %-*s | %-*s | %-*s |",
		colRule, "RULE",
		colSev, "SEVERITY",
		colLine, "LINE",
		colDesc, "DESCRIPTION",
		colFix, "FIX",
	)

	grouped := groupBySource(findings)
	sources := []string{"Dockerfile", "docker-compose.yml"}

	for _, source := range sources {
		group, ok := grouped[source]
		if !ok {
			continue
		}

		sortFindings(group)

		fmt.Printf("\n  %s\n\n", source)
		fmt.Println(border)
		fmt.Println(header)
		fmt.Println(border)

		for _, f := range group {
			descLines := wrapToLines(f.Description, colDesc)
			fixLines := wrapToLines(f.Fix, colFix)

			for len(descLines) < len(fixLines) {
				descLines = append(descLines, "")
			}
			for len(fixLines) < len(descLines) {
				fixLines = append(fixLines, "")
			}

			fmt.Printf("| %-*s | %-*s | %-*d | %-*s | %-*s |\n",
				colRule, f.RuleID,
				colSev, string(f.Severity),
				colLine, f.Line,
				colDesc, descLines[0],
				colFix, fixLines[0],
			)

			for i := 1; i < len(descLines); i++ {
				fmt.Printf("| %-*s | %-*s | %-*s | %-*s | %-*s |\n",
					colRule, "",
					colSev, "",
					colLine, "",
					colDesc, descLines[i],
					colFix, fixLines[i],
				)
			}

			fmt.Println(border)
		}

		c, h, m, l := counts(group)
		fmt.Printf("\n  Summary: %d CRITICAL  %d HIGH  %d MEDIUM  %d LOW\n\n",
			c, h, m, l)
	}
}

// wrapToLines breaks text into a slice of strings each fitting within width
func wrapToLines(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	line := ""

	for _, word := range words {
		if len(line)+len(word)+1 > width {
			lines = append(lines, line)
			line = word
		} else {
			if line == "" {
				line = word
			} else {
				line += " " + word
			}
		}
	}
	if line != "" {
		lines = append(lines, line)
	}

	return lines
}

// wordWrap breaks long text at word boundaries for clean terminal output
func wordWrap(text string, width int, indent string) string {
	words := strings.Fields(text)
	var lines []string
	line := ""

	for _, word := range words {
		if len(line)+len(word)+1 > width {
			lines = append(lines, line)
			line = word
		} else {
			if line == "" {
				line = word
			} else {
				line += " " + word
			}
		}
	}
	if line != "" {
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n"+indent)
}
