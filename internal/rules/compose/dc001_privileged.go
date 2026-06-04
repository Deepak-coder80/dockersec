package compose

import (
	"fmt"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterComposeRule(checkPrivileged)
}

func checkPrivileged(cf *parser.ComposeFile) []models.Finding {
	var findings []models.Finding

	for name, svc := range cf.Services {
		if svc.Privileged {
			findings = append(findings, models.Finding{
				RuleID:   "DC001",
				Severity: models.SeverityCritical,
				Description: fmt.Sprintf("Service '%s' runs with privileged: true. "+
					"Privileged mode gives the container full access to the host kernel, "+
					"all devices, and host namespaces. It completely disables container isolation. "+
					"An attacker who compromises this container has root on the host machine.", name),
				Line: 0,
				Fix:  "Remove 'privileged: true'. If you need specific kernel capabilities, use 'cap_add' to grant only what is required. Example:\n  cap_add:\n    - NET_ADMIN",
			})
		}
	}

	return findings
}
