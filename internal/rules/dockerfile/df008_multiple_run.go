package dockerfile

import (
	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkMultipleRun)
}

func checkMultipleRun(df *parser.ParsedDockerfile) []models.Finding {
	runInstructions := df.FindAllInstructions("RUN")

	// only flag when there are 3 or more consecutive RUN layers
	if len(runInstructions) >= 3 {
		return []models.Finding{
			{
				RuleID:      "DF008",
				Severity:    models.SeverityLow,
				Description: "Multiple RUN instructions create unnecessary image layers",
				Line:        runInstructions[0].Line,
				Fix:         "Chain related commands with && to reduce layers e.g. RUN apt-get update && apt-get install -y curl",
			},
		}
	}

	return nil
}
