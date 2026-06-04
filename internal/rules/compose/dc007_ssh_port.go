package compose

import (
	"fmt"
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterComposeRule(checkSSHPort)
}

func checkSSHPort(cf *parser.ComposeFile) []models.Finding {
	var findings []models.Finding

	for name, svc := range cf.Services {
		for _, port := range svc.Ports {
			// port mapping format is "host:container" or just "container"
			parts := strings.Split(port, ":")
			hostPort := parts[0]

			if hostPort == "22" {
				findings = append(findings, models.Finding{
					RuleID:   "DC007",
					Severity: models.SeverityHigh,
					Description: fmt.Sprintf("Service '%s' exposes port 22 (SSH) on the host. "+
						"Exposing SSH directly from a container to the host is a serious security risk. "+
						"Port 22 is constantly scanned and brute-forced on the internet. "+
						"Containers should not run SSH at all. Use 'docker exec' for shell access instead.", name),
					Line: 0,
					Fix:  "Remove the port 22 mapping. Access the container with:\n  docker exec -it <container_name> /bin/sh",
				})
			}
		}
	}

	return findings
}
