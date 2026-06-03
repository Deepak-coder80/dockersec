package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkAptRecommends)
}

func checkAptRecommends(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("RUN") {
		hasAptGet := strings.Contains(inst.Value, "apt-get install")
		hasFlag := strings.Contains(inst.Value, "--no-install-recommends")

		if hasAptGet && !hasFlag {
			findings = append(findings, models.Finding{
				RuleID:      "DF007",
				Severity:    models.SeverityLow,
				Description: "apt-get install used without --no-install-recommends",
				Line:        inst.Line,
				Fix:         "Use 'apt-get install --no-install-recommends' to reduce image size and attack surface.",
			})
		}
	}

	return findings
}
