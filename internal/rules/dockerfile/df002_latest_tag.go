package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkLatestTag)
}

func checkLatestTag(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("FROM") {
		// value looks like "node:latest" or "node:latest AS builder"
		image := strings.Fields(inst.Value)[0]

		// no tag at all defaults to latest
		if !strings.Contains(image, ":") || strings.HasSuffix(image, ":latest") {
			findings = append(findings, models.Finding{
				RuleID:   "DF002",
				Severity: models.SeverityHigh,
				Description: "Base image uses 'latest' tag: " + image + ". " +
					"The 'latest' tag is not a version. It points to whatever the image maintainer " +
					"last pushed to that name. Your build today and your build next week can produce " +
					"completely different images silently. This breaks reproducibility and makes " +
					"debugging production incidents much harder.",
				Line: inst.Line,
				Fix: "Pin to a specific version and use a minimal base image. Example: node:20.11-alpine3.19\n" +
					"For maximum reproducibility, also pin by digest: node:20.11-alpine3.19@sha256:abc123...",
			})
		}
	}

	return findings
}
