package redact

import (
	"maps"
	"strings"
	"testing"
)

// jsonString returns s as a JSON string literal, for building lines that
// carry JSON inside a string.
func jsonString(s string) string {
	return string(appendString(nil, s))
}

func TestRedactBodyStrings(t *testing.T) {
	e := shippedEngine(t)
	h := Hash

	tests := []struct {
		name   string
		in     string
		want   string
		counts Counts
	}{
		{
			name:   "JSON inside a response body string (line 1)",
			in:     `{"response":{"body":"{\"token\":\"abc123\"}"}}`,
			want:   `{"response":{"body":"{\"token\":\"****\"}"}}`,
			counts: Counts{"secret-fields": 1},
		},
		{
			name:   "JSON inside a request body string (line 10)",
			in:     `{"body":"{\"email\":\"carol@example.com\",\"password\":\"p@ssw0rd!\",\"profile\":{\"card\":\"5555555555554444\"}}"}`,
			want:   `{"body":"{\"email\":\"` + h("carol@example.com") + `\",\"password\":\"****\",\"profile\":{\"card\":\"************4444\"}}"}`,
			counts: Counts{"email": 1, "secret-fields": 1, "credit-card": 1},
		},
		{
			name:   "JSON string inside a body field",
			in:     `{"body":{"payload":"{\"password\":\"x\"}"}}`,
			want:   `{"body":{"payload":"{\"password\":\"****\"}"}}`,
			counts: Counts{"secret-fields": 1},
		},
		{
			name:   "JSON array inside a string",
			in:     `{"body":"[{\"cvv\":\"123\"},\"a@b.com\"]"}`,
			want:   `{"body":"[{},\"` + h("a@b.com") + `\"]"}`,
			counts: Counts{"cvv-fields": 1, "email": 1},
		},
		{
			name:   "clean JSON string keeps its formatting",
			in:     `{"body":"{ \"status\": \"ok\",\n  \"count\": 1 }"}`,
			want:   `{"body":"{ \"status\": \"ok\",\n  \"count\": 1 }"}`,
			counts: Counts{},
		},
		{
			name:   "broken JSON string is scanned as text",
			in:     `{"body":"{\"email\":\"a@b.com\",\"password\":\"x\""}`,
			want:   `{"body":"{\"email\":\"` + h("a@b.com") + `\",\"password\":\"x\""}`,
			counts: Counts{"email": 1},
		},
		{
			name:   "JSON-looking text in a header is not parsed",
			in:     `{"headers":{"X-Data":"{\"password\":\"x\"}"}}`,
			want:   `{"headers":{"X-Data":"{\"password\":\"x\"}"}}`,
			counts: Counts{},
		},
		{
			name:   "form body with Content-Type (line 8)",
			in:     `{"headers":{"Content-Type":"application/x-www-form-urlencoded"},"body":"email=bob%40example.com&password=hunter2&card=4111111111111111&remember=on"}`,
			want:   `{"headers":{"Content-Type":"application/x-www-form-urlencoded"},"body":"email=` + h("bob@example.com") + `&password=****&card=************1111&remember=on"}`,
			counts: Counts{"email": 1, "secret-fields": 1, "credit-card": 1},
		},
		{
			name:   "form body recognised by its shape",
			in:     `{"body":"grant_type=password&client_secret=s3cr3t&cvv=123"}`,
			want:   `{"body":"grant_type=password&client_secret=****"}`,
			counts: Counts{"secret-fields": 1, "cvv-fields": 1},
		},
		{
			name:   "form Content-Type with charset, in the response",
			in:     `{"response":{"headers":{"content-type":["application/x-www-form-urlencoded; charset=utf-8"]},"body":"token=abc def"}}`,
			want:   `{"response":{"headers":{"content-type":["application/x-www-form-urlencoded; charset=utf-8"]},"body":"token=****"}}`,
			counts: Counts{"secret-fields": 1},
		},
		{
			name:   "free text with key=value is not a form (line 41)",
			in:     `{"body":{"debug":"login attempt password=hunter2 for user=zed"}}`,
			want:   `{"body":{"debug":"login attempt password=hunter2 for user=zed"}}`,
			counts: Counts{},
		},
		{
			name:   "base64 body is left alone (line 17)",
			in:     `{"response":{"body":"UEsDBBQAAAAIAA=="}}`,
			want:   `{"response":{"body":"UEsDBBQAAAAIAA=="}}`,
			counts: Counts{},
		},
		{
			name:   "query string in the path (line 30)",
			in:     `{"path":"/v1/reset?token=abc123def456&email=gina%40example.com"}`,
			want:   `{"path":"/v1/reset?token=****&email=` + h("gina@example.com") + `"}`,
			counts: Counts{"secret-fields": 1, "email": 1},
		},
		{
			name:   "path without a query string",
			in:     `{"path":"/v1/users/a@b.com/profile"}`,
			want:   `{"path":"/v1/users/` + h("a@b.com") + `/profile"}`,
			counts: Counts{"email": 1},
		},
		{
			name:   "query string with a fragment and a removed field",
			in:     `{"path":"/pay?cvv=123&page=2#a@b.com"}`,
			want:   `{"path":"/pay?page=2#` + h("a@b.com") + `"}`,
			counts: Counts{"cvv-fields": 1, "email": 1},
		},
		{
			name:   "email used as an object key",
			in:     `{"body":{"users":{"alice@example.com":{"role":"admin"}}}}`,
			want:   `{"body":{"users":{"` + h("alice@example.com") + `":{"role":"admin"}}}}`,
			counts: Counts{"email": 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, counts := redactLine(t, e, tt.in)
			if got != tt.want {
				t.Errorf("RedactLine\n  in %s\n got %s\nwant %s", tt.in, got, tt.want)
			}
			if !maps.Equal(counts, tt.counts) {
				t.Errorf("counts = %v, want %v", counts, tt.counts)
			}
			again, counts := redactLine(t, e, got)
			if again != got || len(counts) != 0 {
				t.Errorf("not idempotent: second run gave %s (counts %v)", again, counts)
			}
		})
	}
}

// JSON can be wrapped in a string several times. Key rules apply up to
// maxEmbedDepth levels; past that the value rules still run on the text.
func TestEmbeddedJSONDepth(t *testing.T) {
	e := shippedEngine(t)

	// wrap(n) builds a body string with the payload n levels deep.
	wrap := func(levels int) string {
		doc := `{"password":"hunter2","note":"a@b.com"}`
		for range levels - 1 {
			doc = `{"inner":` + jsonString(doc) + `}`
		}
		return `{"body":` + jsonString(doc) + `}`
	}

	for levels := 1; levels <= maxEmbedDepth; levels++ {
		got, counts := redactLine(t, e, wrap(levels))
		if strings.Contains(got, "hunter2") || counts["secret-fields"] != 1 {
			t.Errorf("%d levels: password not redacted: %s", levels, got)
		}
	}

	got, counts := redactLine(t, e, wrap(maxEmbedDepth+1))
	if !strings.Contains(got, "hunter2") {
		t.Errorf("%d levels: expected key rules to stop at maxEmbedDepth", maxEmbedDepth+1)
	}
	if strings.Contains(got, "a@b.com") || counts["email"] != 1 {
		t.Errorf("%d levels: value rules must still apply: %s", maxEmbedDepth+1, got)
	}
}

func TestEscapeFormComponent(t *testing.T) {
	tests := []struct{ in, want string }{
		{"****", "****"},
		{"************1111", "************1111"},
		{Hash("x"), Hash("x")},
		{"a&b=c d%e+f#g", "a%26b%3Dc%20d%25e%2Bf%23g"},
		{"é", "%C3%A9"},
		{"tab\there", "tab%09here"},
	}
	for _, tt := range tests {
		if got := escapeFormComponent(tt.in); got != tt.want {
			t.Errorf("escapeFormComponent(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRedactForm(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct {
		name, in, want string
	}{
		{"untouched pairs keep their encoding", "a=x+y&b=%7E&remember=on", "a=x+y&b=%7E&remember=on"},
		{"broken percent-encoding is scanned as text", "a=%zz&password=x", "a=%zz&password=****"},
		{"broken pair with an email", "note=%zz a@b.com", "note=%zz " + Hash("a@b.com")},
		{"field without a value", "flag&password=x", "flag&password=****"},
		{"empty value under a secret key", "password=&x=1", "password=&x=1"},
		{"every field removed", "cvv=1&cvc=2", ""},
		{"encoded field name", "pass%77ord=x", "pass%77ord=****"},
		{"value with spaces is re-encoded", "q=hi+a%40b.com", "q=hi%20" + Hash("a@b.com")},
		{"empty form", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.redactForm(tt.in, "body", nil)
			if got != tt.want {
				t.Errorf("redactForm(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if again := e.redactForm(got, "body", nil); again != got {
				t.Errorf("not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func TestLooksLikeForm(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"a=1", true},
		{"a=1&b=2", true},
		{"email=bob%40example.com&password=hunter2", true},
		{"=1", false},
		{"no equals sign", false},
		{"login password=hunter2", false},
		{"", false},
		{"line1\nkey=value", false},
	}
	for _, tt := range tests {
		if got := looksLikeForm(tt.in); got != tt.want {
			t.Errorf("looksLikeForm(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
