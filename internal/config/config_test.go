package config

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The rules file shipped with the assignment must load, and must load into
// exactly the rules it describes.
func TestLoadShippedRules(t *testing.T) {
	cfg, err := Load("../../rules.yaml")
	if err != nil {
		t.Fatalf("Load(rules.yaml): %v", err)
	}

	wantSettings := Settings{MaskReplacement: "****", PartialKeepLast: 4, PartialFill: "*", HashAlgorithm: "sha256"}
	if cfg.Settings != wantSettings {
		t.Errorf("settings = %+v, want %+v", cfg.Settings, wantSettings)
	}

	wantKey := []struct {
		name   string
		scope  Scope
		action Action
	}{
		{"auth-headers", ScopeHeaders, ActionMask},
		{"credential-headers", ScopeHeaders, ActionMask},
		{"api-key-names", ScopeAny, ActionHash},
		{"secret-fields", ScopeBody, ActionMask},
		{"card-number-fields", ScopeBody, ActionPartial},
		{"cvv-fields", ScopeBody, ActionRemove},
		{"pii-fields", ScopeBody, ActionHash},
	}
	if len(cfg.KeyRules) != len(wantKey) {
		t.Fatalf("got %d key rules, want %d", len(cfg.KeyRules), len(wantKey))
	}
	for i, w := range wantKey {
		r := cfg.KeyRules[i]
		if r.Name != w.name || r.Scope != w.scope || r.Action != w.action {
			t.Errorf("key_rules[%d] = {%s %s %s}, want {%s %s %s}", i, r.Name, r.Scope, r.Action, w.name, w.scope, w.action)
		}
		if wantScheme := r.Name == "auth-headers"; r.PreserveScheme != wantScheme {
			t.Errorf("key_rules[%d] %s: PreserveScheme = %v, want %v", i, r.Name, r.PreserveScheme, wantScheme)
		}
	}

	wantValue := []struct {
		name      string
		validator string
		action    Action
	}{
		{"email", "", ActionHash},
		{"jwt", "", ActionMask},
		{"credit-card", ValidatorLuhn, ActionPartial},
		{"api-key-prefix", "", ActionMask},
		{"secret-assignment", "", ActionMask},
	}
	if len(cfg.ValueRules) != len(wantValue) {
		t.Fatalf("got %d value rules, want %d", len(cfg.ValueRules), len(wantValue))
	}
	for i, w := range wantValue {
		r := cfg.ValueRules[i]
		if r.Name != w.name || r.Validator != w.validator || r.Action != w.action || r.Pattern == nil {
			t.Errorf("value_rules[%d] = {%s %q %s pattern=%v}, want {%s %q %s}", i, r.Name, r.Validator, r.Action, r.Pattern, w.name, w.validator, w.action)
		}
	}
}

func TestDefaultsWhenSettingsOmitted(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
value_rules:
  - name: email
    pattern: '[a-z]+@[a-z]+\.com'
    action: hash
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := Settings{MaskReplacement: "****", PartialKeepLast: 4, PartialFill: "*", HashAlgorithm: "sha256"}
	if cfg.Settings != want {
		t.Errorf("settings = %+v, want defaults %+v", cfg.Settings, want)
	}
}

func TestExplicitSettings(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
settings:
  mask:    { replacement: "[REDACTED]" }
  partial: { keep_last: 0, fill: "#" }
  hash:    { algorithm: SHA256 }
value_rules:
  - { name: email, pattern: '[a-z]+@[a-z]+\.com', action: hash }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// keep_last: 0 is a real value (mask everything), not "unset".
	want := Settings{MaskReplacement: "[REDACTED]", PartialKeepLast: 0, PartialFill: "#", HashAlgorithm: "sha256"}
	if cfg.Settings != want {
		t.Errorf("settings = %+v, want %+v", cfg.Settings, want)
	}
}

// Every way a rules file can be wrong must be rejected with a message that
// points at the problem.
func TestParseRejectsInvalidConfig(t *testing.T) {
	const oneRule = `
value_rules:
  - { name: email, pattern: 'x@y\.com', action: hash }
`
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"empty file", ``, "empty"},
		{"only a comment", "# nothing here\n", "empty"},
		{"not YAML", "version: [1,\n", "invalid YAML"},
		{"two documents", "version: 1\n" + oneRule + "---\nversion: 1\n", "single YAML document"},
		{"unknown top-level field", "version: 1\nrulez: []\n" + oneRule, "rulez"},
		{"typo inside a rule", `
version: 1
key_rules:
  - { name: a, scope: body, match: { exact: [x] }, acton: mask }
`, "acton"},
		{"missing version", oneRule, "unsupported version 0"},
		{"future version", "version: 2\n" + oneRule, "unsupported version 2"},
		{"no rules at all", "version: 1\n", "no rules defined"},
		{"empty rule lists", "version: 1\nkey_rules: []\nvalue_rules: []\n", "no rules defined"},

		{"key rule without name", `
version: 1
key_rules:
  - { scope: body, match: { exact: [x] }, action: mask }
`, "name is required"},
		{"duplicate name across lists", `
version: 1
key_rules:
  - { name: email, scope: body, match: { exact: [email] }, action: mask }
value_rules:
  - { name: email, pattern: 'x@y\.com', action: hash }
`, `duplicate rule name "email"`},
		{"bad scope", `
version: 1
key_rules:
  - { name: a, scope: query, match: { exact: [x] }, action: mask }
`, `invalid scope "query"`},
		{"missing scope", `
version: 1
key_rules:
  - { name: a, match: { exact: [x] }, action: mask }
`, `invalid scope ""`},
		{"bad key action", `
version: 1
key_rules:
  - { name: a, scope: body, match: { exact: [x] }, action: encrypt }
`, `invalid action "encrypt"`},
		{"exact and regex", `
version: 1
key_rules:
  - { name: a, scope: body, match: { exact: [x], regex: 'x' }, action: mask }
`, "not both"},
		{"no matcher", `
version: 1
key_rules:
  - { name: a, scope: body, match: {}, action: mask }
`, "needs exact or regex"},
		{"empty exact name", `
version: 1
key_rules:
  - { name: a, scope: body, match: { exact: [x, ""] }, action: mask }
`, "empty name"},
		{"preserve_scheme with remove", `
version: 1
key_rules:
  - { name: a, scope: headers, match: { exact: [Authorization] }, action: remove, preserve_scheme: true }
`, "preserve_scheme has no effect"},
		{"broken key regex", `
version: 1
key_rules:
  - { name: a, scope: body, match: { regex: '(unclosed' }, action: mask }
`, "invalid regex"},

		{"value rule without pattern", `
version: 1
value_rules:
  - { name: a, action: mask }
`, "pattern is required"},
		{"broken value pattern", `
version: 1
value_rules:
  - { name: a, pattern: '[a-', action: mask }
`, "invalid pattern"},
		{"pattern matches empty string", `
version: 1
value_rules:
  - { name: a, pattern: '\d*', action: mask }
`, "empty string"},
		{"pattern matches mask replacement", `
version: 1
value_rules:
  - { name: stars, pattern: '\*{3,}', action: mask }
`, "not be idempotent"},
		{"unknown validator", `
version: 1
value_rules:
  - { name: a, pattern: '\d+', validator: iban, action: mask }
`, `unknown validator "iban"`},
		{"bad value action", `
version: 1
value_rules:
  - { name: a, pattern: '\d+', action: shred }
`, `invalid action "shred"`},

		{"empty mask replacement", "version: 1\nsettings: { mask: { replacement: \"\" } }\n" + oneRule, "replacement must not be empty"},
		{"negative keep_last", "version: 1\nsettings: { partial: { keep_last: -1 } }\n" + oneRule, "keep_last must be >= 0"},
		{"multi-char fill", "version: 1\nsettings: { partial: { fill: \"**\" } }\n" + oneRule, "exactly one character"},
		{"empty fill", "version: 1\nsettings: { partial: { fill: \"\" } }\n" + oneRule, "exactly one character"},
		{"unsupported hash", "version: 1\nsettings: { hash: { algorithm: md5 } }\n" + oneRule, `"md5" is not supported`},
		{"keep_last not a number", "version: 1\nsettings: { partial: { keep_last: four } }\n" + oneRule, "invalid YAML"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse succeeded (%d key, %d value rules), want error containing %q", len(cfg.KeyRules), len(cfg.ValueRules), tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q\nwant it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// An operator fixing a broken file should see every problem at once, not one
// per attempt.
func TestParseReportsAllErrorsTogether(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
key_rules:
  - { name: a, scope: nowhere, match: { exact: [x] }, action: mask }
value_rules:
  - { name: b, pattern: '(', action: mask }
  - { name: c, pattern: '\d+', action: zap }
`))
	if err == nil {
		t.Fatal("Parse succeeded, want errors")
	}
	for _, want := range []string{`"a": invalid scope`, `"b": invalid pattern`, `"c": invalid action`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q:\n%s", want, err)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("does-not-exist.yaml"); err == nil {
		t.Fatal("Load of a missing file succeeded")
	}
}

// Key matching, checked against the shipped rules and the key names that
// appear in input.ndjson.
func TestKeyRuleMatches(t *testing.T) {
	cfg, err := Load("../../rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]*KeyRule{}
	for i := range cfg.KeyRules {
		rules[cfg.KeyRules[i].Name] = &cfg.KeyRules[i]
	}

	tests := []struct {
		rule string
		key  string
		want bool
	}{
		// Header names are case-insensitive (input lines 1, 2, 14).
		{"auth-headers", "Authorization", true},
		{"auth-headers", "authorization", true},
		{"auth-headers", "AUTHORIZATION", true},
		{"auth-headers", "Set-Cookie", true},
		{"auth-headers", "Cookie", true},
		{"auth-headers", "Content-Type", false},
		{"auth-headers", "Authorization-Hint", false},

		// Every api-key spelling from lines 14 and 27.
		{"api-key-names", "X-Api-Key", true},
		{"api-key-names", "x-api-key", true},
		{"api-key-names", "X-API-KEY", true},
		{"api-key-names", "api_key", true},
		{"api-key-names", "ApiKey", true},
		{"api-key-names", "api-key", true},
		{"api-key-names", "api_key_id", false},

		{"secret-fields", "password", true},
		{"secret-fields", "PASSWORD", true},
		{"secret-fields", "Client_Secret", true},
		{"secret-fields", "pwd", true},
		// Look-alikes from line 48 must not be redacted: the regex is anchored.
		{"secret-fields", "password_hint", false},
		{"secret-fields", "passwordless", false},
		{"secret-fields", "tokenizer", false},
		{"secret-fields", "secret_santa", false},

		{"card-number-fields", "card_number", true},
		{"card-number-fields", "cardnumber", true},
		{"card-number-fields", "pan", true},
		{"card-number-fields", "card", false},

		{"cvv-fields", "cvv", true},
		{"cvv-fields", "CVC", true},
		{"cvv-fields", "cvv_hint", false},
	}
	for _, tt := range tests {
		r, ok := rules[tt.rule]
		if !ok {
			t.Fatalf("rule %q not found", tt.rule)
		}
		if got := r.Matches(tt.key); got != tt.want {
			t.Errorf("%s.Matches(%q) = %v, want %v", tt.rule, tt.key, got, tt.want)
		}
	}
}

func TestKeyRuleAppliesTo(t *testing.T) {
	tests := []struct {
		scope   Scope
		headers bool
		body    bool
	}{
		{ScopeHeaders, true, false},
		{ScopeBody, false, true},
		{ScopeAny, true, true},
	}
	for _, tt := range tests {
		r := KeyRule{Scope: tt.scope}
		if got := r.AppliesTo(ScopeHeaders); got != tt.headers {
			t.Errorf("scope %s: AppliesTo(headers) = %v, want %v", tt.scope, got, tt.headers)
		}
		if got := r.AppliesTo(ScopeBody); got != tt.body {
			t.Errorf("scope %s: AppliesTo(body) = %v, want %v", tt.scope, got, tt.body)
		}
	}
}

// kustomize only reads files inside deploy/k8s, so the rules deployed to
// Kubernetes are a copy. The copy must not drift from the repo's rules.
func TestDeployRulesMatchRepoRules(t *testing.T) {
	repo, err := os.ReadFile("../../rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	deployed, err := os.ReadFile("../../deploy/k8s/rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repo, deployed) {
		t.Error("deploy/k8s/rules.yaml differs from rules.yaml; copy rules.yaml over it")
	}
}
