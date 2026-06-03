package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkCurlBash)
}

// piping curl directly to bash is dangerous because you execute remote code
// without any verification of what it contains
func checkCurlBash(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	dangerous := []string{"curl | bash", "curl|bash", "wget | bash", "wget|bash"}

	for _, inst := range df.FindAllInstructions("RUN") {
		normalized := strings.ReplaceAll(inst.Value, " ", "")
		for _, pattern := range dangerous {
			if strings.Contains(normalized, strings.ReplaceAll(pattern, " ", "")) {
				findings = append(findings, models.Finding{
					RuleID:      "DF006",
					Severity:    models.SeverityCritical,
					Description: "Piping curl or wget directly to bash: " + inst.Value,
					Line:        inst.Line,
					Fix:         "Download the script, verify its checksum, then execute it.",
				})
				break
			}
		}
	}

	return findings
}
