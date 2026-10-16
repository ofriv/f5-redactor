package redact

import (
	"maps"
	"regexp"
	"strings"
	"testing"

	"f5-redactor/internal/config"
)

// shippedEngine builds an Engine from the rules.yaml in the repo root.
func shippedEngine(t *testing.T) *Engine {
	t.Helper()
	cfg, err := config.Load("../../rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg)
}

// engineFrom builds an Engine from an inline rules document.
func engineFrom(t *testing.T, yaml string) *Engine {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg)
}

// Free-text strings taken from input.ndjson, redacted with the shipped rules.
func TestRedactTextShippedRules(t *testing.T) {
	e := shippedEngine(t)
	h := Hash

	tests := []struct {
		name   string
		in     string
		want   string
		counts Counts
	}{
		{
			name:   "no sensitive data",
			in:     "Hi team, the deploy is done.",
			want:   "Hi team, the deploy is done.",
			counts: Counts{},
		},
		{
			name:   "empty string",
			in:     "",
			want:   "",
			counts: Counts{},
		},
		{
			name:   "three emails with punctuation (line 29)",
			in:     "mail bob@example.com,carol@example.com;dave@example.com.",
			want:   "mail " + h("bob@example.com") + "," + h("carol@example.com") + ";" + h("dave@example.com") + ".",
			counts: Counts{"email": 3},
		},
		{
			name:   "only Luhn-valid numbers are cards (line 40)",
			in:     "first 4111111111111111 then 4111111111111112 then 5555555555554444.",
			want:   "first ************1111 then 4111111111111112 then ************4444.",
			counts: Counts{"credit-card": 2},
		},
		{
			name:   "order ref that fails Luhn (line 4)",
			in:     "order ref 4111111111111112 was shipped",
			want:   "order ref 4111111111111112 was shipped",
			counts: Counts{},
		},
		{
			name:   "request id that fails Luhn (line 35)",
			in:     "request id 1705312800123456 took 12ms",
			want:   "request id 1705312800123456 took 12ms",
			counts: Counts{},
		},
		{
			name:   "email and api key in a ticket (line 9)",
			in:     "please reset the account for dave@example.com. Temporary key: sk_live_9fA2kLmQ7x. Thanks!",
			want:   "please reset the account for " + h("dave@example.com") + ". Temporary key: ****. Thanks!",
			counts: Counts{"email": 1, "api-key-prefix": 1},
		},
		{
			name:   "stack trace in a response (line 42)",
			in:     "panic: auth failed for ivan@example.com token sk_live_Zz91Qw2Lm\n\tgoroutine 1 [running]:",
			want:   "panic: auth failed for " + h("ivan@example.com") + " token ****\n\tgoroutine 1 [running]:",
			counts: Counts{"email": 1, "api-key-prefix": 1},
		},
		{
			name:   "emoji right next to the values (line 46)",
			in:     "💳4111111111111111💳 and 😀zed@example.com😀",
			want:   "💳************1111💳 and 😀" + h("zed@example.com") + "😀",
			counts: Counts{"credit-card": 1, "email": 1},
		},
		{
			name:   "hebrew text (line 47)",
			in:     "מספר כרטיס: 4111111111111111 אימייל: user@example.com",
			want:   "מספר כרטיס: ************1111 אימייל: " + h("user@example.com"),
			counts: Counts{"credit-card": 1, "email": 1},
		},
		{
			name:   "japanese text (line 7)",
			in:     "名前: 田中 email tanaka@example.co.jp 😀 カード 4012888888881881 です",
			want:   "名前: 田中 email " + h("tanaka@example.co.jp") + " 😀 カード ************1881 です",
			counts: Counts{"email": 1, "credit-card": 1},
		},
		{
			name:   "email inside HTML (line 31)",
			in:     "<html><body>Hello hank@example.com</body></html>",
			want:   "<html><body>Hello " + h("hank@example.com") + "</body></html>",
			counts: Counts{"email": 1},
		},
		{
			name:   "not emails (line 29)",
			in:     "not-an-email@ a@b x@y.z",
			want:   "not-an-email@ a@b x@y.z",
			counts: Counts{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counts := Counts{}
			got := e.RedactText(tt.in, counts)
			if got != tt.want {
				t.Errorf("RedactText(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
			if !maps.Equal(counts, tt.counts) {
				t.Errorf("counts = %v, want %v", counts, tt.counts)
			}
		})
	}
}

// Running the redactor on its own output must change nothing and count
// nothing.
func TestRedactTextIdempotent(t *testing.T) {
	e := shippedEngine(t)
	inputs := []string{
		"mail bob@example.com,carol@example.com;dave@example.com.",
		"first 4111111111111111 then 4111111111111112 then 5555555555554444.",
		"key sk_live_9fA2kLmQ7x and sk_test_abc",
		"💳4111111111111111💳 and 😀zed@example.com😀",
		"already redacted: ************1111 **** " + Hash("x@y.com"),
		"a hash next to digits: " + Hash("x") + "4111111111111111",
	}
	for _, in := range inputs {
		once := e.RedactText(in, nil)
		counts := Counts{}
		twice := e.RedactText(once, counts)
		if twice != once {
			t.Errorf("not idempotent for %q\n once %q\ntwice %q", in, once, twice)
		}
		if len(counts) != 0 {
			t.Errorf("second run on %q counted redactions: %v", in, counts)
		}
	}
}

// A hash from an earlier run is left alone even when a rule would match
// part of it.
func TestRedactTextLeavesHashesAlone(t *testing.T) {
	e := engineFrom(t, `
version: 1
value_rules:
  - { name: hex-run, pattern: '[0-9a-f]{8,}', action: mask }
`)
	in := "id " + Hash("x") + " and deadbeefcafe"
	want := "id " + Hash("x") + " and ****"
	if got := e.RedactText(in, nil); got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// Overlapping matches are merged so that no piece of either match leaks.
func TestRedactTextOverlappingMatches(t *testing.T) {
	tests := []struct {
		name   string
		rules  string
		in     string
		want   string
		counts Counts
	}{
		{
			// "abc-123" and "123-xyz" overlap on "123". Picking only one of
			// them would leave "xyz" or "abc" in the output.
			name: "partial overlap: whole region masked, first rule wins",
			rules: `
  - { name: first, pattern: 'abc-\d+', action: mask }
  - { name: second, pattern: '\d+-xyz', action: hash }
`,
			in:     "id abc-123-xyz end",
			want:   "id **** end",
			counts: Counts{"first": 1},
		},
		{
			name: "rule order decides, not position in the text",
			rules: `
  - { name: first, pattern: '\d+-xyz', action: mask }
  - { name: second, pattern: 'abc-\d+', action: remove }
`,
			in:     "id abc-123-xyz end",
			want:   "id **** end",
			counts: Counts{"first": 1},
		},
		{
			// Partial would keep the last 4 characters of the merged region,
			// which belong to the other rule's match.
			name: "partial is upgraded to mask when rules overlap",
			rules: `
  - { name: card, pattern: '\d{8}', action: partial }
  - { name: tail, pattern: '\d{4}[a-z]{4}', action: remove }
`,
			in:     "x 12345678abcd y",
			want:   "x **** y",
			counts: Counts{"card": 1},
		},
		{
			name: "partial is upgraded even when one match is inside the other",
			rules: `
  - { name: card, pattern: '\d{8}', action: partial }
  - { name: inner, pattern: '3456', action: partial }
`,
			in:     "x 12345678 y",
			want:   "x **** y",
			counts: Counts{"card": 1},
		},
		{
			name: "nested match: whole outer region gets the first rule's action",
			rules: `
  - { name: inner, pattern: 'secret', action: hash }
  - { name: outer, pattern: 'my-secret-value', action: mask }
`,
			in:     "[my-secret-value]",
			want:   "[" + Hash("my-secret-value") + "]",
			counts: Counts{"inner": 1},
		},
		{
			name: "adjacent matches are separate regions",
			rules: `
  - { name: a, pattern: 'aaa', action: mask }
  - { name: b, pattern: 'bbb', action: remove }
`,
			in:     "aaabbb",
			want:   "****",
			counts: Counts{"a": 1, "b": 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := engineFrom(t, "version: 1\nvalue_rules:\n"+tt.rules)
			counts := Counts{}
			if got := e.RedactText(tt.in, counts); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if !maps.Equal(counts, tt.counts) {
				t.Errorf("counts = %v, want %v", counts, tt.counts)
			}
		})
	}
}

// Removing text can create a new match out of the pieces around it. The
// re-scan must catch it.
func TestRedactTextRescansAfterRemove(t *testing.T) {
	e := engineFrom(t, `
version: 1
value_rules:
  - { name: email, pattern: '[a-z]+@[a-z]+\.com', action: hash }
  - { name: junk, pattern: '#', action: remove }
`)
	counts := Counts{}
	got := e.RedactText("contact bob@exa#mple.com now", counts)
	want := "contact " + Hash("bob@example.com") + " now"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !maps.Equal(counts, Counts{"junk": 1, "email": 1}) {
		t.Errorf("counts = %v", counts)
	}
}

// A rule set whose replacement keeps creating new matches must not loop
// forever. Config validation rejects such rules; this builds one by hand.
func TestRedactTextStopsAfterMaxPasses(t *testing.T) {
	cfg := config.Config{
		Settings:   config.Settings{MaskReplacement: "zz"},
		ValueRules: []config.ValueRule{{Name: "z", Pattern: regexp.MustCompile("z"), Action: config.ActionMask}},
	}
	counts := Counts{}
	got := New(&cfg).RedactText("z", counts)
	if want := strings.Repeat("z", 1<<maxTextPasses); got != want {
		t.Errorf("got %d characters, want %d", len(got), len(want))
	}
	if counts["z"] == 0 {
		t.Error("no redactions counted")
	}
}

func TestValidateUnknownValidatorFailsClosed(t *testing.T) {
	if !validate("no-such-validator", "anything") {
		t.Error("an unknown validator must keep the match (redact rather than leak)")
	}
	if !validate("", "anything") {
		t.Error("no validator must keep the match")
	}
	if validate(config.ValidatorLuhn, "4111111111111112") {
		t.Error("luhn accepted an invalid number")
	}
}

func TestNilCountsIsAllowed(t *testing.T) {
	e := shippedEngine(t)
	if got := e.RedactText("x a@b.com", nil); got != "x "+Hash("a@b.com") {
		t.Errorf("got %q", got)
	}
}
