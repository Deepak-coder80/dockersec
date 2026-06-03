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
				RuleID:      "DF001",
				Severity:    models.SeverityHigh,
				Description: "Container runs as root. No USER instruction found.",
				Line:        1,
				Fix:         "Add 'USER nonroot' before your CMD or ENTRYPOINT.",
			},
		}
	}
	return nil
}

