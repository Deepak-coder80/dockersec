package dockerfile

import (
	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkHealthcheck)
}

func checkHealthcheck(df *parser.ParsedDockerfile) []models.Finding {
	if df.FindInstruction("HEALTHCHECK") == nil {
		return []models.Finding{
			{
				RuleID:      "DF005",
				Severity:    models.SeverityLow,
				Description: "No HEALTHCHECK instruction defined",
				Line:        1,
				Fix:         "Add HEALTHCHECK so orchestrators like Kubernetes and Docker Swarm know when your container is healthy.",
			},
		}
	}
	return nil
}
