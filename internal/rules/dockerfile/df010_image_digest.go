package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkImageDigest)
}

// digest pinning looks like node@sha256:abc123...
// a tag alone can be overwritten silently in a registry
func checkImageDigest(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("FROM") {
		image := strings.Fields(inst.Value)[0]

		// skip scratch, it has no digest
		if image == "scratch" {
			continue
		}

		if !strings.Contains(image, "@sha256:") {
			findings = append(findings, models.Finding{
				RuleID:      "DF010",
				Severity:    models.SeverityMedium,
				Description: "Base image not pinned by digest: " + image,
				Line:        inst.Line,
				Fix:         "Pin by digest for reproducible builds e.g. node:20.11-alpine3.19@sha256:abc123...",
			})
		}
	}

	return findings
}
