package compose

import (
	"fmt"
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterComposeRule(checkDockerSocket)
}

func checkDockerSocket(cf *parser.ComposeFile) []models.Finding {
	var findings []models.Finding

	for name, svc := range cf.Services {
		for _, vol := range svc.Volumes {
			if strings.Contains(vol, "/var/run/docker.sock") {
				findings = append(findings, models.Finding{
					RuleID:   "DC002",
					Severity: models.SeverityHigh,
					Description: fmt.Sprintf("Service '%s' mounts the Docker socket. "+
						"The Docker socket gives full control over the Docker daemon. "+
						"Any process inside this container can create new containers, "+
						"mount host filesystems, and escalate to full host root access. "+
						"This is effectively the same as running privileged.", name),
					Line: 0,
					Fix:  "Remove the Docker socket mount. If you need container management, use a dedicated API or a tool like Portainer with restricted access.",
				})
			}
		}
	}

	return findings
}
