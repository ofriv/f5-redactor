package redact

import (
	"regexp"

	"f5-redactor/internal/config"
)

// Engine applies a validated rule set. It holds no mutable state, so one
// Engine can be shared by many goroutines.
type Engine struct {
	keyRules   []config.KeyRule
	valueRules []config.ValueRule
	actions    Actions

	// For value rules with a validator, the pattern anchored at the start
	// (^...) and at both ends (^...$), indexed like valueRules. Used to look
	// for a shorter or later match when the validator rejects the first one.
	anchoredStart []*regexp.Regexp
	anchoredFull  []*regexp.Regexp
}

// New builds an Engine from a validated config.
func New(cfg *config.Config) *Engine {
	e := &Engine{
		keyRules:      cfg.KeyRules,
		valueRules:    cfg.ValueRules,
		actions:       NewActions(cfg.Settings),
		anchoredStart: make([]*regexp.Regexp, len(cfg.ValueRules)),
		anchoredFull:  make([]*regexp.Regexp, len(cfg.ValueRules)),
	}
	for i, r := range cfg.ValueRules {
		if r.Validator != "" {
			// The pattern already compiled once, so wrapping it cannot fail.
			e.anchoredStart[i] = regexp.MustCompile(`^(?:` + r.Pattern.String() + `)`)
			e.anchoredFull[i] = regexp.MustCompile(`^(?:` + r.Pattern.String() + `)$`)
		}
	}
	return e
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
