package redact

import (
	"errors"
	"strings"
	"testing"
)

func roundTrip(t *testing.T, in string) string {
	t.Helper()
	n, err := parseJSON([]byte(in))
	if err != nil {
		t.Fatalf("parseJSON(%q): %v", in, err)
	}
	return string(appendJSON(nil, n))
}

// Untouched JSON must come out exactly as it went in (for compact input).
func TestJSONRoundTripKeepsDocument(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"key order", `{"b":1,"a":2,"c":3}`},
		{"duplicate keys (line 25)", `{"email":"first@example.com","email":"second@example.com"}`},
		{"nested", `{"a":{"b":[1,[2,[3]],{"c":null}]}}`},
		{"literals", `[true,false,null]`},
		{"empty containers", `{"o":{},"a":[]}`},
		{"numbers as written (line 28)", `[10.50,1.0,1e3,-0,12345678901234567890,4111111111111111,1E-7]`},
		{"html characters stay raw", `{"note":"Tom & Jerry <tom@example.com>"}`},
		{"non-ASCII stays raw", `{"note":"מספר כרטיס 名前 Zürich 😀"}`},
		{"required escapes", `{"s":"quote \" backslash \\ newline \n tab \t"}`},
		{"control characters", `{"s":"\u0000\u0001\u001f"}`},
		{"top-level scalars", `42`},
		{"top-level string", `"hello"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := roundTrip(t, tt.in); got != tt.in {
				t.Errorf("round trip changed the document\n got %s\nwant %s", got, tt.in)
			}
		})
	}
}

func TestJSONRoundTripNormalizes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"whitespace removed", " { \"a\" : [ 1 , 2 ] } ", `{"a":[1,2]}`},
		{"unneeded escapes decoded (line 45)", `{"contact":"alice@example.com","x":"é\/"}`, `{"contact":"alice@example.com","x":"é/"}`},
		{"carriage return escaped", `"a\rb"`, `"a\rb"`},
		{"escaped surrogate pair", `"😀"`, `"😀"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := roundTrip(t, tt.in)
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
			if again := roundTrip(t, got); again != got {
				t.Errorf("second round trip changed it: %s", again)
			}
		})
	}
}

func TestParseJSONErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", ``, ErrEmpty},
		{"spaces only (line 22)", `   `, ErrEmpty},
		{"truncated (line 20)", `{"ts":"x","headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi`, ErrInvalidJSON},
		{"truncated (line 50)", `{"body":{"email":"trunc@exam`, ErrInvalidJSON},
		{"plain log line (line 21)", `2025-01-15 10:00:20 WARN upstream timeout user=erin@example.com retry=3`, ErrInvalidJSON},
		{"trailing data", `{"a":1} x`, ErrInvalidJSON},
		{"two values on one line", `{"a":1}{"b":2}`, ErrInvalidJSON},
		{"extra closing brace", `{"a":1}}`, ErrInvalidJSON},
		{"missing value", `{"a":}`, ErrInvalidJSON},
		{"trailing comma", `{"a":1,}`, ErrInvalidJSON},
		{"unclosed array", `[1,2`, ErrInvalidJSON},
		{"non-string key", `{1:2}`, ErrInvalidJSON},
		{"bad literal", `nul`, ErrInvalidJSON},
		{"raw control character in string", "\"a\x00b\"", ErrInvalidJSON},
		{"single quotes", `{'a':1}`, ErrInvalidJSON},
		{"too deep", strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1), ErrTooDeep},
		{"too deep objects", strings.Repeat(`{"a":`, maxDepth+1) + "1" + strings.Repeat("}", maxDepth+1), ErrTooDeep},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseJSON([]byte(tt.in))
			if !errors.Is(err, tt.want) {
				t.Fatalf("parseJSON error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseJSONMaxDepthAllowed(t *testing.T) {
	in := strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth)
	if got := roundTrip(t, in); got != in {
		t.Errorf("nesting of exactly maxDepth changed: %s", got)
	}
}

// Errors are fixed values: they must never carry input text, which may be
// sensitive, into logs.
func TestParseJSONErrorsDoNotQuoteInput(t *testing.T) {
	for _, in := range []string{
		`{"password":"hunter2"`,
		`{"card":"4111111111111111",}`,
		`token=sk_live_abc123`,
	} {
		_, err := parseJSON([]byte(in))
		if err == nil {
			t.Fatalf("parseJSON(%q) succeeded", in)
		}
		for _, secret := range []string{"hunter2", "4111111111111111", "sk_live_abc123"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q quotes the input", err)
			}
		}
	}
}
