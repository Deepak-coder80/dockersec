package compose

import (
	"fmt"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterComposeRule(checkResourceLimits)
}

func checkResourceLimits(cf *parser.ComposeFile) []models.Finding {
	var findings []models.Finding

	for name, svc := range cf.Services {
		// no deploy block or no limits set means unbounded resource usage
		if svc.Deploy == nil ||
			(svc.Deploy.Resources.Limits.CPUs == "" &&
				svc.Deploy.Resources.Limits.Memory == "") {
			findings = append(findings, models.Finding{
				RuleID:   "DC004",
				Severity: models.SeverityMedium,
				Description: fmt.Sprintf("Service '%s' has no CPU or memory limits. "+
					"Without limits a single container can consume all available host resources. "+
					"This causes other services on the same host to starve and crash. "+
					"In a multi-tenant environment this is a denial of service risk.", name),
				Line: 0,
				Fix: "Add resource limits under the deploy block. Example:\n" +
					"  deploy:\n    resources:\n      limits:\n        cpus: '0.5'\n        memory: 512M",
			})
		}
	}

	return findings
}
