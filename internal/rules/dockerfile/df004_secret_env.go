package dockerfile

import (
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkSecretEnv)
}

// keywords that suggest a value is a secret
var secretKeywords = []string{
	"secret", "password", "passwd", "token",
	"api_key", "apikey", "private_key", "access_key",
	"secret_key", "auth", "credential",
}

func checkSecretEnv(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("ENV") {
		key := strings.ToLower(strings.Fields(inst.Value)[0])

		for _, keyword := range secretKeywords {
			if strings.Contains(key, keyword) {
				findings = append(findings, models.Finding{
					RuleID:      "DF004",
					Severity:    models.SeverityCritical,
					Description: "Possible secret in ENV instruction: " + strings.Fields(inst.Value)[0],
					Line:        inst.Line,
					Fix:         "Use Docker secrets or environment injection at runtime. Never hardcode credentials.",
				})
				break
			}
		}
	}

	return findings
}
