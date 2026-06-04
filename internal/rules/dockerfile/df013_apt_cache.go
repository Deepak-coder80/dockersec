package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkAptCache)
}

func checkAptCache(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("RUN") {
		hasAptGet := strings.Contains(inst.Value, "apt-get install")
		// package manager cache left in the image adds size with zero runtime benefit
		hasCleanup := strings.Contains(inst.Value, "rm -rf /var/lib/apt/lists")

		if hasAptGet && !hasCleanup {
			findings = append(findings, models.Finding{
				RuleID:   "DF013",
				Severity: models.SeverityLow,
				Description: "apt-get install found without cache cleanup. " +
					"After apt-get installs packages, it leaves downloaded package lists and cached files in /var/lib/apt/lists. " +
					"These files serve no purpose at runtime and can add tens of megabytes to your image. " +
					"Every unnecessary megabyte increases pull time, storage cost, and potential vulnerability surface.",
				Line: inst.Line,
				Fix:  "Add cleanup in the same RUN instruction. Example:\n  RUN apt-get update && apt-get install -y --no-install-recommends curl \\\n    && rm -rf /var/lib/apt/lists/*",
			})
		}
	}

	return findings
}
