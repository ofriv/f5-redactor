package redact

import "f5-redactor/internal/config"

// Engine applies a validated rule set. It holds no mutable state, so one
// Engine can be shared by many goroutines.
type Engine struct {
	keyRules   []config.KeyRule
	valueRules []config.ValueRule
	actions    Actions
}

// New builds an Engine from a validated config.
func New(cfg *config.Config) *Engine {
	return &Engine{
		keyRules:   cfg.KeyRules,
		valueRules: cfg.ValueRules,
		actions:    NewActions(cfg.Settings),
	}
}

// RuleNames returns the names of all rules, key rules first, in config order.
func (e *Engine) RuleNames() []string {
	names := make([]string, 0, len(e.keyRules)+len(e.valueRules))
	for _, r := range e.keyRules {
		names = append(names, r.Name)
	}
	for _, r := range e.valueRules {
		names = append(names, r.Name)
	}
	return names
}

// Counts records how many redactions each rule made, keyed by rule name.
// A nil Counts is allowed and records nothing.
type Counts map[string]int

func (c Counts) add(rule string) {
	if c != nil {
		c[rule]++
	}
}

func (c Counts) merge(other Counts) {
	if c != nil {
		for rule, n := range other {
			c[rule] += n
		}
	}
}

// validators maps a validator name from rules.yaml to its check.
var validators = map[string]func(string) bool{
	config.ValidatorLuhn: Luhn,
}

// validate runs the named validator on a match. An unknown validator cannot
// get past config validation; if one ever did, the match is kept (fail
// closed: redact rather than leak).
func validate(name, match string) bool {
	if name == "" {
		return true
	}
	check, ok := validators[name]
	if !ok {
		return true
	}
	return check(match)
}
