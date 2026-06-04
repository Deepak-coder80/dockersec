package compose

import (
	"fmt"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterComposeRule(checkHostNetwork)
}

func checkHostNetwork(cf *parser.ComposeFile) []models.Finding {
	var findings []models.Finding

	for name, svc := range cf.Services {
		if svc.NetworkMode == "host" {
			findings = append(findings, models.Finding{
				RuleID:   "DC003",
				Severity: models.SeverityHigh,
				Description: fmt.Sprintf("Service '%s' uses network_mode: host. "+
					"Host networking removes all network isolation between the container and the host. "+
					"The container shares the host network stack directly. "+
					"Any port the container listens on is immediately exposed on the host, "+
					"bypassing your firewall and port mapping rules.", name),
				Line: 0,
				Fix:  "Remove network_mode: host. Define explicit port mappings instead.\n  ports:\n    - \"8080:8080\"",
			})
		}
	}

	return findings
}
