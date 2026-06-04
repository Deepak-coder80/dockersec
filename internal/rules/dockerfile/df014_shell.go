package dockerfile

import (
	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkShell)
}

func checkShell(df *parser.ParsedDockerfile) []models.Finding {
	if df.FindInstruction("SHELL") == nil {
		return []models.Finding{
			{
				RuleID:   "DF014",
				Severity: models.SeverityLow,
				Description: "No SHELL instruction defined. " +
					"Docker uses /bin/sh -c as the default shell for RUN instructions. " +
					"This is unpredictable across base images and platforms. " +
					"On some minimal images, /bin/sh may be busybox ash, not bash, " +
					"causing subtle script failures in production that are hard to debug.",
				Line: 1,
				Fix:  "Explicitly declare your shell at the top of the Dockerfile. Example:\n  SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]",
			},
		}
	}
	return nil
}
