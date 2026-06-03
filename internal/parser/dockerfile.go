package parser

import (
	"os"
	"strings"

	"github.com/Deepak-coder80/dockersec/internal/models"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

type DockerfileInstruction struct {
	Command string
	Value   string
	Line    int
}

type ParsedDockerfile struct {
	Instructions []DockerfileInstruction
	Path         string
}

func ParseDockerfile(path string) (*ParsedDockerfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result, err := parser.Parse(f)
	if err != nil {
		return nil, err
	}

	parsed := &ParsedDockerfile{Path: path}

	for _, node := range result.AST.Children {
		inst := DockerfileInstruction{
			Command: strings.ToUpper(node.Value),
			Line:    node.StartLine,
		}

		// build the full value by walking all sibling nodes
		var parts []string
		for n := node.Next; n != nil; n = n.Next {
			if n.Value != "" {
				parts = append(parts, n.Value)
			}
		}
		inst.Value = strings.Join(parts, " ")

		parsed.Instructions = append(parsed.Instructions, inst)
	}

	return parsed, nil
}

// FindInstruction returns the first instruction matching a command name
func (p *ParsedDockerfile) FindInstruction(command string) *DockerfileInstruction {
	for i, inst := range p.Instructions {
		if inst.Command == command {
			return &p.Instructions[i]
		}
	}
	return nil
}

// FindAllInstructions returns all instructions matching a command name
func (p *ParsedDockerfile) FindAllInstructions(command string) []DockerfileInstruction {
	var results []DockerfileInstruction
	for _, inst := range p.Instructions {
		if inst.Command == command {
			results = append(results, inst)
		}
	}
	return results
}

// keep models import available for future rule use
var _ = models.SeverityCritical
