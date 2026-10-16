// Package config loads and validates the redaction rules file (rules.yaml).
//
// Loading is deliberately strict: an unknown field, a regex that does not
// compile, an unsupported action or an empty rule set is a hard error. The
// redactor must never start with rules that are silently weaker than what the
// operator wrote, because the failure mode of a weak rule is leaked data.
//
// The YAML is first decoded into raw* structs that mirror the file format,
// then validated and converted into Config, whose regexes are already
// compiled. Code outside this package only ever sees a valid Config.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Action is what a rule does to the data it matches.
type Action string

const (
	ActionMask    Action = "mask"    // replace with the mask replacement ("****")
	ActionPartial Action = "partial" // keep the last N characters, fill the rest
	ActionHash    Action = "hash"    // replace with the SHA-256 of the value
	ActionRemove  Action = "remove"  // key rules: drop the key; value rules: delete the text
)

// Scope says which part of a transaction a key rule applies to.
type Scope string

const (
	ScopeHeaders Scope = "headers" // request and response headers
	ScopeBody    Scope = "body"    // request and response bodies
	ScopeAny     Scope = "any"     // both
)

// ValidatorLuhn is the only validator currently supported for value rules.
const ValidatorLuhn = "luhn"

// SupportedVersion is the only config format version this build understands.
const SupportedVersion = 1

// Config is a fully validated rule set, ready for the redaction engine.
type Config struct {
	Settings   Settings
	KeyRules   []KeyRule
	ValueRules []ValueRule
}

// Settings holds the parameters shared by all rules that use an action.
type Settings struct {
	MaskReplacement string // e.g. "****"
	PartialKeepLast int    // how many trailing characters partial keeps
	PartialFill     string // a single character used to fill the rest
	HashAlgorithm   string // only "sha256" is supported
}

// KeyRule matches on the name of a JSON key or an HTTP header.
type KeyRule struct {
	Name   string
	Scope  Scope
	Action Action

	// Exactly one of exact / re is set.
	exact map[string]struct{} // lower-cased names, matched case-insensitively
	re    *regexp.Regexp
}

// Matches reports whether a key or header name is covered by this rule.
//
// Exact names are compared case-insensitively: HTTP header names are
// case-insensitive (RFC 9110), and the sample input contains Authorization,
// authorization and AUTHORIZATION. Regex rules are applied as written, so a
// regex that should ignore case must say so with (?i).
func (r *KeyRule) Matches(name string) bool {
	if r.re != nil {
		return r.re.MatchString(name)
	}
	_, ok := r.exact[strings.ToLower(name)]
	return ok
}

// AppliesTo reports whether the rule is active in the given part of a
// transaction (ScopeHeaders or ScopeBody).
func (r *KeyRule) AppliesTo(where Scope) bool {
	return r.Scope == ScopeAny || r.Scope == where
}

// ValueRule matches on the content of a string, whatever its key is called.
type ValueRule struct {
	Name      string
	Pattern   *regexp.Regexp
	Validator string // "" or ValidatorLuhn
	Action    Action
}

// Load reads and validates the rules file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("rules file %s: %w", path, err)
	}
	return cfg, nil
}

// Parse validates a rules document. All validation problems are reported
// together, so an operator can fix a broken file in one pass.
func Parse(data []byte) (*Config, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a typo such as "acton:" is an error, not a silently ignored field
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("rules file is empty")
		}
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("rules file must contain a single YAML document")
	}
	return raw.validate()
}

// --- file format -----------------------------------------------------------

// The raw* types mirror rules.yaml. Optional settings are pointers so that
// "not set" (use the default) can be told apart from an explicit value.

type rawConfig struct {
	Version    int            `yaml:"version"`
	Settings   rawSettings    `yaml:"settings"`
	KeyRules   []rawKeyRule   `yaml:"key_rules"`
	ValueRules []rawValueRule `yaml:"value_rules"`
}

type rawSettings struct {
	Mask struct {
		Replacement *string `yaml:"replacement"`
	} `yaml:"mask"`
	Partial struct {
		KeepLast *int    `yaml:"keep_last"`
		Fill     *string `yaml:"fill"`
	} `yaml:"partial"`
	Hash struct {
		Algorithm *string `yaml:"algorithm"`
	} `yaml:"hash"`
}

type rawKeyRule struct {
	Name  string `yaml:"name"`
	Scope string `yaml:"scope"`
	Match struct {
		Exact []string `yaml:"exact"`
		Regex string   `yaml:"regex"`
	} `yaml:"match"`
	Action string `yaml:"action"`
}

type rawValueRule struct {
	Name      string `yaml:"name"`
	Pattern   string `yaml:"pattern"`
	Validator string `yaml:"validator"`
	Action    string `yaml:"action"`
}

// --- validation ------------------------------------------------------------

func (raw *rawConfig) validate() (*Config, error) {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if raw.Version != SupportedVersion {
		fail("unsupported version %d (this build supports version %d)", raw.Version, SupportedVersion)
	}

	settings, settingsErrs := raw.Settings.validate()
	errs = append(errs, settingsErrs...)

	if len(raw.KeyRules) == 0 && len(raw.ValueRules) == 0 {
		// Valid YAML with no rules would pass every log through unredacted.
		fail("no rules defined: refusing to run with an empty rule set")
	}

	// Rule names label the per-rule counts in the summary, so they must be
	// present and unique across both lists.
	seen := map[string]string{}
	checkName := func(kind string, i int, name string) {
		if strings.TrimSpace(name) == "" {
			fail("%s[%d]: name is required", kind, i)
			return
		}
		if prev, dup := seen[name]; dup {
			fail("%s[%d]: duplicate rule name %q (already used in %s)", kind, i, name, prev)
			return
		}
		seen[name] = fmt.Sprintf("%s[%d]", kind, i)
	}

	cfg := &Config{Settings: settings}

	for i, r := range raw.KeyRules {
		checkName("key_rules", i, r.Name)
		label := fmt.Sprintf("key_rules[%d] %q", i, r.Name)
		rule := KeyRule{Name: r.Name, Scope: Scope(r.Scope), Action: Action(r.Action)}

		switch rule.Scope {
		case ScopeHeaders, ScopeBody, ScopeAny:
		default:
			fail("%s: invalid scope %q (want headers, body or any)", label, r.Scope)
		}
		if !validAction(rule.Action) {
			fail("%s: invalid action %q (want mask, partial, hash or remove)", label, r.Action)
		}

		hasExact, hasRegex := len(r.Match.Exact) > 0, r.Match.Regex != ""
		switch {
		case hasExact && hasRegex:
			fail("%s: match must have either exact or regex, not both", label)
		case hasExact:
			rule.exact = make(map[string]struct{}, len(r.Match.Exact))
			for _, name := range r.Match.Exact {
				if strings.TrimSpace(name) == "" {
					fail("%s: exact match contains an empty name", label)
					continue
				}
				rule.exact[strings.ToLower(name)] = struct{}{}
			}
		case hasRegex:
			re, err := regexp.Compile(r.Match.Regex)
			if err != nil {
				fail("%s: invalid regex: %v", label, err)
			}
			rule.re = re
		default:
			fail("%s: match needs exact or regex", label)
		}
		cfg.KeyRules = append(cfg.KeyRules, rule)
	}

	for i, r := range raw.ValueRules {
		checkName("value_rules", i, r.Name)
		label := fmt.Sprintf("value_rules[%d] %q", i, r.Name)
		rule := ValueRule{Name: r.Name, Validator: r.Validator, Action: Action(r.Action)}

		if !validAction(rule.Action) {
			fail("%s: invalid action %q (want mask, partial, hash or remove)", label, r.Action)
		}
		if r.Validator != "" && r.Validator != ValidatorLuhn {
			fail("%s: unknown validator %q (supported: luhn)", label, r.Validator)
		}

		if r.Pattern == "" {
			fail("%s: pattern is required", label)
		} else if re, err := regexp.Compile(r.Pattern); err != nil {
			fail("%s: invalid pattern: %v", label, err)
		} else {
			// A pattern that matches the empty string would "match" between
			// every pair of characters.
			if re.MatchString("") {
				fail("%s: pattern must not match the empty string", label)
			}
			// If a pattern matched the mask replacement, redacted output would
			// be redacted again on every run, which breaks idempotency.
			if settings.MaskReplacement != "" && re.MatchString(settings.MaskReplacement) {
				fail("%s: pattern matches the mask replacement %q; output would not be idempotent", label, settings.MaskReplacement)
			}
			rule.Pattern = re
		}
		cfg.ValueRules = append(cfg.ValueRules, rule)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

func (raw *rawSettings) validate() (Settings, []error) {
	s := Settings{
		MaskReplacement: "****",
		PartialKeepLast: 4,
		PartialFill:     "*",
		HashAlgorithm:   "sha256",
	}
	var errs []error

	if v := raw.Mask.Replacement; v != nil {
		if *v == "" {
			errs = append(errs, errors.New("settings.mask.replacement must not be empty (use action: remove to delete values)"))
		}
		s.MaskReplacement = *v
	}
	if v := raw.Partial.KeepLast; v != nil {
		if *v < 0 {
			errs = append(errs, fmt.Errorf("settings.partial.keep_last must be >= 0, got %d", *v))
		}
		s.PartialKeepLast = *v
	}
	if v := raw.Partial.Fill; v != nil {
		if utf8.RuneCountInString(*v) != 1 {
			errs = append(errs, fmt.Errorf("settings.partial.fill must be exactly one character, got %q", *v))
		}
		s.PartialFill = *v
	}
	if v := raw.Hash.Algorithm; v != nil {
		if !strings.EqualFold(*v, "sha256") {
			errs = append(errs, fmt.Errorf("settings.hash.algorithm %q is not supported (supported: sha256)", *v))
		}
		s.HashAlgorithm = "sha256"
	}
	return s, errs
}

func validAction(a Action) bool {
	switch a {
	case ActionMask, ActionPartial, ActionHash, ActionRemove:
		return true
	}
	return false
}
