package dockerfile

import (
	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkRootUser)
}

// checkRootUser flags when no USER instruction is present
// running as root is dangerous because any process breakout gets full host access
func checkRootUser(df *parser.ParsedDockerfile) []models.Finding {
	if df.FindInstruction("USER") == nil {
		return []models.Finding{
			{
				RuleID:   "DF001",
				Severity: models.SeverityHigh,
				Description: "No USER instruction found. Container will run as root. " +
					"Root inside a container maps directly to root on the host kernel. " +
					"If an attacker exploits your application and breaks out of the container, " +
					"they have full root access to the host machine. " +
					"This is one of the most common and critical Docker misconfigurations in production.",
				Line: 1,
				Fix: "Add a non-root user and switch to it before your final CMD or ENTRYPOINT. Example:\n" +
					"  RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser\n" +
					"  USER appuser",
			},
		}
	}
	return nil
}
