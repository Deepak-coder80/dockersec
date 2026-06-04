package models

// Severity levels for finding
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type Finding struct {
	RuleID      string
	Severity    Severity
	Description string
	Line        int
	Instruction string
	Fix         string
	Source      string
}
