package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkPipCache)
}

func checkPipCache(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("RUN") {
		hasPip := strings.Contains(inst.Value, "pip install")
		hasNoCache := strings.Contains(inst.Value, "--no-cache-dir")

		if hasPip && !hasNoCache {
			findings = append(findings, models.Finding{
				RuleID:   "DF016",
				Severity: models.SeverityLow,
				Description: "pip install used without --no-cache-dir. " +
					"pip caches downloaded packages in ~/.cache/pip by default. " +
					"In a Docker build this cache is written into your image layer and never used again. " +
					"It adds image size with zero benefit since each build starts fresh.",
				Line: inst.Line,
				Fix:  "Always pass --no-cache-dir to pip install.\n  Example: RUN pip install --no-cache-dir -r requirements.txt",
			})
		}
	}

	return findings
}
