package dockerfile

import (
	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkAddInstruction)
}

func checkAddInstruction(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("ADD") {
		findings = append(findings, models.Finding{
			RuleID:      "DF003",
			Severity:    models.SeverityMedium,
			Description: "ADD instruction used instead of COPY",
			Line:        inst.Line,
			Fix:         "Use COPY unless you specifically need ADD's tar extraction or URL fetching.",
		})
	}

	return findings
}
