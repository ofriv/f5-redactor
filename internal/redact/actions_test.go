package redact

import (
	"strings"
	"testing"
	"unicode/utf8"

	"f5-redactor/internal/config"
)

// Settings as in the shipped rules.yaml.
var defaultSettings = config.Settings{MaskReplacement: "****", PartialKeepLast: 4, PartialFill: "*", HashAlgorithm: "sha256"}

func TestMask(t *testing.T) {
	a := NewActions(defaultSettings)
	for _, v := range []string{"hunter2", "Bearer eyJhbGciOi.x.y", "x", "****"} {
		if got := a.Mask(v); got != "****" {
			t.Errorf("Mask(%q) = %q, want ****", v, got)
		}
	}
	custom := NewActions(config.Settings{MaskReplacement: "[REDACTED]"})
	if got := custom.Mask("secret"); got != "[REDACTED]" {
		t.Errorf("custom Mask = %q, want [REDACTED]", got)
	}
}

func TestPartial(t *testing.T) {
	a := NewActions(defaultSettings)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"visa", "4111111111111111", "************1111"},
		{"amex 15 digits", "378282246310005", "***********0005"},
		{"with spaces", "4111 1111 1111 1111", "***************1111"},
		{"five chars", "12345", "*2345"},
		// Keeping the last 4 of a value of 4 or fewer would reveal it all.
		{"exactly keep_last", "1234", "****"},
		{"shorter than keep_last", "123", "***"},
		{"single char", "7", "*"},
		// Already partially masked input (line 12) must come out unchanged.
		{"already masked", "************1111", "************1111"},
		{"all stars", "****", "****"},
		// Count characters, not bytes.
		{"hebrew", "כרטיס אשראי", "*******שראי"},
		{"emoji", "💳💳💳💳💳💳", "**💳💳💳💳"},
		{"japanese", "カード番号です", "***番号です"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.Partial(tt.in)
			if got != tt.want {
				t.Fatalf("Partial(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if utf8.RuneCountInString(got) != utf8.RuneCountInString(tt.in) {
				t.Errorf("length changed: %d -> %d characters", utf8.RuneCountInString(tt.in), utf8.RuneCountInString(got))
			}
			if again := a.Partial(got); again != got {
				t.Errorf("not idempotent: Partial(%q) = %q", got, again)
			}
		})
	}
}

func TestPartialCustomSettings(t *testing.T) {
	tests := []struct {
		keepLast int
		fill     string
		in       string
		want     string
	}{
		{0, "*", "secret", "******"},
		{2, "#", "secret", "####et"},
		{4, "•", "4111111111111111", "••••••••••••1111"},
	}
	for _, tt := range tests {
		a := NewActions(config.Settings{PartialKeepLast: tt.keepLast, PartialFill: tt.fill})
		if got := a.Partial(tt.in); got != tt.want {
			t.Errorf("keep_last=%d fill=%q: Partial(%q) = %q, want %q", tt.keepLast, tt.fill, tt.in, got, tt.want)
		}
	}
}

func TestHash(t *testing.T) {
	// Known SHA-256 test vector.
	const abc = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := Hash("abc"); got != abc {
		t.Errorf("Hash(abc) = %q, want %q", got, abc)
	}

	for _, v := range []string{"a@b.com", "sk_live_abc123", "שלום", "\x00\x01binary"} {
		h := Hash(v)
		if !IsHashed(h) {
			t.Errorf("Hash(%q) = %q, not recognised by IsHashed", v, h)
		}
		if strings.Contains(h, v) {
			t.Errorf("Hash(%q) = %q still contains the input", v, h)
		}
		if again := Hash(h); again != h {
			t.Errorf("not idempotent: Hash(%q) = %q", h, again)
		}
	}

	if Hash("a@b.com") == Hash("A@b.com") {
		t.Error("different inputs produced the same hash")
	}
}

// Only exact Hash output counts as already hashed; anything that merely
// looks similar must still be hashed.
func TestIsHashed(t *testing.T) {
	valid := Hash("x")
	tests := []struct {
		in   string
		want bool
	}{
		{valid, true},
		{strings.TrimPrefix(valid, "sha256:"), false},   // no prefix
		{valid[:len(valid)-1], false},                   // 63 hex digits
		{valid + "0", false},                            // 65 hex digits
		{"sha256:" + strings.ToUpper(valid[7:]), false}, // upper-case hex
		{"sha256:" + strings.Repeat("g", 64), false},    // not hex
		{"note sha256:" + valid[7:], false},             // embedded in text
		{"sha256:", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsHashed(tt.in); got != tt.want {
			t.Errorf("IsHashed(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestApply(t *testing.T) {
	a := NewActions(defaultSettings)
	tests := []struct {
		action config.Action
		in     string
		want   string
	}{
		{config.ActionMask, "hunter2", "****"},
		{config.ActionPartial, "4111111111111111", "************1111"},
		{config.ActionHash, "abc", "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{config.ActionRemove, "secret", ""},
		// An empty string has nothing to hide and stays empty for every action.
		{config.ActionMask, "", ""},
		{config.ActionPartial, "", ""},
		{config.ActionHash, "", ""},
		{config.ActionRemove, "", ""},
		// Unknown action: fail closed by masking.
		{config.Action("bogus"), "secret", "****"},
	}
	for _, tt := range tests {
		if got := a.Apply(tt.action, tt.in); got != tt.want {
			t.Errorf("Apply(%s, %q) = %q, want %q", tt.action, tt.in, got, tt.want)
		}
	}
}
