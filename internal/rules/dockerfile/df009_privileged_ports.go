package dockerfile

import (
	"strconv"
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

func init() {
	rules.RegisterDockerfileRule(checkPrivilegedPort)
}

func checkPrivilegedPort(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding

	for _, inst := range df.FindAllInstructions("EXPOSE") {
		// port can be "80" or "80/tcp"
		portStr := strings.Split(strings.Fields(inst.Value)[0], "/")[0]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		if port < 1024 {
			findings = append(findings, models.Finding{
				RuleID:      "DF009",
				Severity:    models.SeverityMedium,
				Description: "Privileged port exposed: " + portStr,
				Line:        inst.Line,
				Fix:         "Use ports above 1024. Privileged ports require root to bind.",
			})
		}
	}

	return findings
}
