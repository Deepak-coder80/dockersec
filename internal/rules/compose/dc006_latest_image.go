package compose

import (
	"fmt"
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterComposeRule(checkLatestImage)
}

func checkLatestImage(cf *parser.ComposeFile) []models.Finding {
	var findings []models.Finding

	for name, svc := range cf.Services {
		if svc.Image == "" {
			continue
		}

		if !strings.Contains(svc.Image, ":") || strings.HasSuffix(svc.Image, ":latest") {
			findings = append(findings, models.Finding{
				RuleID:   "DC006",
				Severity: models.SeverityHigh,
				Description: fmt.Sprintf("Service '%s' uses image without a pinned version: %s. "+
					"Unpinned images pull whatever is currently tagged latest in the registry. "+
					"A registry update can silently change your running service on the next deploy "+
					"or host restart.", name, svc.Image),
				Line: 0,
				Fix:  "Pin to a specific image version.\n  image: postgres:16.2-alpine3.19",
			})
		}
	}

	return findings
}
