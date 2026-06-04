package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkAptUpdateSeparate)
}

func checkAptUpdateSeparate(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding
	var updateLine int

	for _, inst := range df.FindAllInstructions("RUN") {
		hasUpdate := strings.Contains(inst.Value, "apt-get update")
		hasInstall := strings.Contains(inst.Value, "apt-get install")

		// track the last RUN that only does apt-get update
		if hasUpdate && !hasInstall {
			updateLine = inst.Line
		}

		// if a separate RUN later does the install, that is a cache busting problem
		if !hasUpdate && hasInstall && updateLine > 0 {
			findings = append(findings, models.Finding{
				RuleID:   "DF017",
				Severity: models.SeverityMedium,
				Description: "apt-get update and apt-get install are in separate RUN instructions. " +
					"Docker caches each layer independently. If the apt-get update layer is cached, " +
					"Docker skips it and runs apt-get install against a stale package list. " +
					"This causes builds to install outdated or unavailable package versions silently.",
				Line: updateLine,
				Fix:  "Always combine apt-get update and apt-get install in one RUN instruction.\n  Example: RUN apt-get update && apt-get install -y --no-install-recommends curl",
			})
			updateLine = 0
		}
	}

	return findings
}
