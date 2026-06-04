package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkNpmProduction)
}

func checkNpmProduction(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("RUN") {
		hasNpmInstall := strings.Contains(inst.Value, "npm install")
		hasProductionFlag := strings.Contains(inst.Value, "--production") ||
			strings.Contains(inst.Value, "--omit=dev") ||
			strings.Contains(inst.Value, "npm ci")

		if hasNpmInstall && !hasProductionFlag {
			findings = append(findings, models.Finding{
				RuleID:   "DF015",
				Severity: models.SeverityMedium,
				Description: "npm install used without --production flag. " +
					"By default npm install includes all devDependencies: test frameworks, linters, build tools, type definitions. " +
					"None of these belong in a production image. They increase image size, " +
					"introduce unnecessary packages with their own CVEs, and slow down container startup.",
				Line: inst.Line,
				Fix:  "Use 'npm ci --production' in production builds. npm ci is faster and uses package-lock.json for exact versions.\n  Example: RUN npm ci --production",
			})
		}
	}

	return findings
}
