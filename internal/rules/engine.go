package rules

import (
	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/Deepak-coder80/dockersec/internal/parser"
)

// RuleFunc is the signature every rule must follow
type RuleFunc func(df *parser.ParsedDockerfile) []models.Finding

// all registered dockerfile rules
var dockerfileRules []RuleFunc

func RegisterDockerfileRule(r RuleFunc) {
	dockerfileRules = append(dockerfileRules, r)
}

// RunDockerfileRules runs all registered rules against a parsed dockerfile
func RunDockerfileRules(df *parser.ParsedDockerfile) []models.Finding {
	var findings []models.Finding
	for _, rule := range dockerfileRules {
		findings = append(findings, rule(df)...)
	}
	return findings
}
