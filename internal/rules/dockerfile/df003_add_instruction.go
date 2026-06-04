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
			RuleID:   "DF003",
			Severity: models.SeverityMedium,
			Description: "ADD instruction used instead of COPY. " +
				"ADD has two hidden behaviors most developers do not expect: " +
				"it automatically extracts tar archives, and it can fetch files from remote URLs. " +
				"These behaviors make your build unpredictable and harder to audit. " +
				"If someone provides a malicious tar file or URL, ADD will silently execute it.",
			Line: inst.Line,
			Fix: "Use COPY for copying local files. It does exactly one thing and is explicit.\n" +
				"Only use ADD when you specifically need tar extraction.",
		})
	}

	return findings
}
