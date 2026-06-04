package yamlrules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
	"github.com/Deepak-coder80/dockersec/internal/rules"
)

// LoadRulesFromDir reads all .yml files from a directory and registers them
func LoadRulesFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// no rules directory is fine, not an error
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		rule, err := LoadRuleFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid rule file %s: %s\n", path, err)
			continue
		}

		if err := validateRule(rule, path); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping rule %s: %s\n", path, err)
			continue
		}

		registerYAMLRule(rule)
	}

	return nil
}

// validateRule checks a rule has the minimum required fields
func validateRule(rule *YAMLRule, path string) error {
	if rule.ID == "" {
		return fmt.Errorf("missing id in %s", path)
	}
	if rule.Type != "dockerfile" && rule.Type != "compose" {
		return fmt.Errorf("invalid type '%s' in %s: must be dockerfile or compose", rule.Type, path)
	}
	if rule.Severity == "" {
		return fmt.Errorf("missing severity in %s", path)
	}
	if rule.Description == "" {
		return fmt.Errorf("missing description in %s", path)
	}
	if rule.Fix == "" {
		return fmt.Errorf("missing fix in %s", path)
	}
	return nil
}

// registerYAMLRule wraps a YAMLRule into a RuleFunc and registers it
func registerYAMLRule(rule *YAMLRule) {
	switch rule.Type {
	case "dockerfile":
		rules.RegisterDockerfileRule(makeDockerfileRule(rule))
	case "compose":
		rules.RegisterComposeRule(makeComposeRule(rule))
	}
}

// makeDockerfileRule builds a RuleFunc from a YAML dockerfile rule
func makeDockerfileRule(rule *YAMLRule) rules.RuleFunc {
	return func(df *parser.ParsedDockerfile) []models.Finding {
		var findings []models.Finding

		for _, inst := range df.FindAllInstructions(strings.ToUpper(rule.Match.Instruction)) {
			if rule.Match.Contains != "" && !strings.Contains(inst.Value, rule.Match.Contains) {
				continue
			}

			findings = append(findings, models.Finding{
				RuleID:      rule.ID,
				Severity:    models.Severity(rule.Severity),
				Description: strings.TrimSpace(rule.Description),
				Line:        inst.Line,
				Fix:         strings.TrimSpace(rule.Fix),
			})
		}

		return findings
	}
}

// makeComposeRule builds a RuleComposeFunc from a YAML compose rule
func makeComposeRule(rule *YAMLRule) rules.RuleComposeFunc {
	return func(cf *parser.ComposeFile) []models.Finding {
		var findings []models.Finding

		for name, svc := range cf.Services {
			if !matchComposeService(rule.Match, svc) {
				continue
			}

			findings = append(findings, models.Finding{
				RuleID:      rule.ID,
				Severity:    models.Severity(rule.Severity),
				Description: fmt.Sprintf("[%s] %s", name, strings.TrimSpace(rule.Description)),
				Line:        0,
				Fix:         strings.TrimSpace(rule.Fix),
			})
		}

		return findings
	}
}

// matchComposeService checks if a service matches a compose rule's match block
func matchComposeService(match MatchRule, svc parser.ComposeService) bool {
	switch match.Field {
	case "image":
		return match.Equals != "" && svc.Image == match.Equals
	case "restart":
		return match.Equals != "" && svc.Restart == match.Equals
	case "network_mode":
		return match.Equals != "" && svc.NetworkMode == match.Equals
	}
	return false
}
