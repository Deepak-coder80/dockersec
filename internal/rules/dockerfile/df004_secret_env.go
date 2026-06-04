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
					RuleID:   "DF004",
					Severity: models.SeverityCritical,
					Description: "Possible secret in ENV instruction: " + strings.Fields(inst.Value)[0] + ". " +
						"ENV values are baked permanently into the image layer. " +
						"Anyone who pulls your image can run 'docker inspect' or 'docker history' " +
						"and read every ENV value in plain text. " +
						"If you push this image to a registry, your secret is exposed to everyone with pull access.",
					Line: inst.Line,
					Fix: "Never put secrets in ENV or ARG. Use runtime secret injection instead:\n" +
						"  - Docker: use --env-file or Docker secrets\n" +
						"  - Kubernetes: use Secrets mounted as env vars\n" +
						"  - CI/CD: inject via your pipeline secret manager at runtime",
				})
				break
			}
		}
	}

	return findings
}
