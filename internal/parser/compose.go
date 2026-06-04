package parser

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ComposeFile represents the top level of a docker-compose.yml
type ComposeFile struct {
	Services map[string]ComposeService `yaml:"services"`
	Path     string
}

// ComposeService represents a single service block
type ComposeService struct {
	Image       string         `yaml:"image"`
	Privileged  bool           `yaml:"privileged"`
	NetworkMode string         `yaml:"network_mode"`
	Restart     string         `yaml:"restart"`
	Environment ComposeEnv     `yaml:"environment"`
	Volumes     []string       `yaml:"volumes"`
	Ports       []string       `yaml:"ports"`
	Deploy      *ComposeDeploy `yaml:"deploy"`
}

// ComposeEnv holds environment variables normalised to a map
// regardless of whether the compose file uses list or map style
type ComposeEnv struct {
	Values map[string]string
}

func (e *ComposeEnv) UnmarshalYAML(value *yaml.Node) error {
	e.Values = make(map[string]string)

	switch value.Kind {

	// map style: KEY: value
	case yaml.MappingNode:
		var m map[string]string
		if err := value.Decode(&m); err != nil {
			return err
		}
		e.Values = m

	// list style: - KEY=value
	case yaml.SequenceNode:
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		for _, item := range list {
			parts := splitEnvItem(item)
			e.Values[parts[0]] = parts[1]
		}
	}

	return nil
}

// splitEnvItem splits "KEY=value" into ["KEY", "value"]
// handles values that contain = signs
func splitEnvItem(item string) [2]string {
	for i, ch := range item {
		if ch == '=' {
			return [2]string{item[:i], item[i+1:]}
		}
	}
	return [2]string{item, ""}
}

// ComposeDeploy holds resource limit configuration
type ComposeDeploy struct {
	Resources ComposeResources `yaml:"resources"`
}

type ComposeResources struct {
	Limits ComposeLimits `yaml:"limits"`
}

type ComposeLimits struct {
	CPUs   string `yaml:"cpus"`
	Memory string `yaml:"memory"`
}

func ParseCompose(path string) (*ComposeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cf ComposeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}

	cf.Path = path
	return &cf, nil
}
