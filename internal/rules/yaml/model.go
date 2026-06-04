package yamlrules

import (
	"os"

	"gopkg.in/yaml.v3"
)

// YAMLRule defines the structure of a rule written in YAML
type YAMLRule struct {
	ID          string    `yaml:"id"`
	Type        string    `yaml:"type"` // dockerfile or compose
	Severity    string    `yaml:"severity"`
	Description string    `yaml:"description"`
	Fix         string    `yaml:"fix"`
	Match       MatchRule `yaml:"match"`
}

// MatchRule defines what pattern to look for
type MatchRule struct {
	// dockerfile fields
	Instruction string `yaml:"instruction"` // RUN, ENV, COPY etc
	Contains    string `yaml:"contains"`    // substring to match in instruction value

	// compose fields
	Field  string `yaml:"field"`  // service field: image, restart etc
	Equals string `yaml:"equals"` // exact value to match
}

func LoadRuleFile(path string) (*YAMLRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rule YAMLRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, err
	}

	return &rule, nil
}
