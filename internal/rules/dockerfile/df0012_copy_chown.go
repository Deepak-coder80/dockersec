package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkCopyChown)
}

func checkCopyChown(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("COPY") {
		// --chown flag sets file ownership at copy time without an extra RUN chown
		if !strings.Contains(inst.Value, "--chown") {
			findings = append(findings, models.Finding{
				RuleID:   "DF012",
				Severity: models.SeverityLow,
				Description: "COPY instruction at line " + string(rune('0'+inst.Line)) + " does not use --chown. " +
					"Files copied into a container default to root ownership even if you switch to a non-root user later. " +
					"This means your app process may not be able to read or write its own files, " +
					"or worse, files owned by root could be modified if there is a privilege escalation.",
				Line: inst.Line,
				Fix:  "Use COPY --chown=<user>:<group> to set correct ownership at copy time. Example: COPY --chown=appuser:appuser . /app",
			})
		}
	}

	return findings
}
