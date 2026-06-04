package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkSudo)
}

func checkSudo(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("RUN") {
		if strings.Contains(inst.Value, "sudo ") {
			findings = append(findings, models.Finding{
				RuleID:   "DF018",
				Severity: models.SeverityHigh,
				Description: "sudo used inside a RUN instruction. " +
					"During Docker build, RUN instructions execute as root by default. " +
					"Using sudo is redundant and signals a misunderstanding of how Docker builds work. " +
					"More critically, if sudo is installed in your final image and an attacker gains " +
					"code execution as a non-root user, sudo becomes a direct privilege escalation path.",
				Line: inst.Line,
				Fix: "Remove sudo from your RUN instructions. Docker build runs as root already. " +
					"If you need to run something as a specific user, use the USER instruction before that RUN block.",
			})
		}
	}

	return findings
}
