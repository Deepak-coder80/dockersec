package compose

import (
	"fmt"
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterComposeRule(checkSecretEnv)
}

var secretKeywords = []string{
	"secret", "password", "passwd", "token",
	"api_key", "apikey", "private_key", "access_key",
	"secret_key", "auth", "credential",
}

func checkSecretEnv(cf *parser.ComposeFile) []models.Finding {
	var findings []models.Finding

	for name, svc := range cf.Services {
		for key, val := range svc.Environment.Values {
			keyLower := strings.ToLower(key)
			for _, keyword := range secretKeywords {
				if strings.Contains(keyLower, keyword) && val != "" {
					findings = append(findings, models.Finding{
						RuleID:   "DC005",
						Severity: models.SeverityCritical,
						Description: fmt.Sprintf("Service '%s' has a possible hardcoded secret in environment: %s. "+
							"Secrets in docker-compose.yml get committed to version control. "+
							"Anyone with repo access can read them. "+
							"They also appear in 'docker inspect' output on the host.", name, key),
						Line: 0,
						Fix: "Use an .env file excluded from git, or Docker secrets.\n" +
							"  environment:\n    - API_KEY=${API_KEY}\n" +
							"Then set the value in a .env file and add .env to .gitignore.",
					})
					break
				}
			}
		}
	}

	return findings
}
