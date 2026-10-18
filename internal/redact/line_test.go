package redact

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"strings"
	"testing"
)

func redactLine(t *testing.T, e *Engine, in string) (string, Counts) {
	t.Helper()
	counts := Counts{}
	out, _, err := e.RedactLine([]byte(in), counts)
	if err != nil {
		t.Fatalf("RedactLine(%s): %v", in, err)
	}
	return string(out), counts
}

func TestRedactLine(t *testing.T) {
	e := shippedEngine(t)
	h := Hash

	tests := []struct {
		name   string
		in     string
		want   string
		counts Counts
	}{
		{
			// A body field named Authorization is not a header; a header
			// named password is caught by the header rule credential-headers.
			name:   "header rules apply to headers only",
			in:     `{"headers":{"Authorization":"Bearer abc","X-Api-Key":"k","Content-Type":"application/json","password":"p"},"body":{"password":"p","Authorization":"x"}}`,
			want:   `{"headers":{"Authorization":"Bearer ****","X-Api-Key":"` + h("k") + `","Content-Type":"application/json","password":"****"},"body":{"password":"****","Authorization":"x"}}`,
			counts: Counts{"auth-headers": 1, "api-key-names": 1, "credential-headers": 1, "secret-fields": 1},
		},
		{
			name:   "header names in any case (lines 2 and 14)",
			in:     `{"headers":{"authorization":"Bearer a","AUTHORIZATION":"Basic dXNlcjpwYXNz","x-api-key":"demo_key_1","X-API-KEY":"demo_key_2","Cookie":"session=abc123; theme=dark"}}`,
			want:   `{"headers":{"authorization":"Bearer ****","AUTHORIZATION":"Basic ****","x-api-key":"` + h("demo_key_1") + `","X-API-KEY":"` + h("demo_key_2") + `","Cookie":"****"}}`,
			counts: Counts{"auth-headers": 3, "api-key-names": 2},
		},
		{
			name:   "response headers and body (line 31)",
			in:     `{"response":{"status":200,"headers":{"Set-Cookie":["session=abc123; HttpOnly","csrf=zzz"]},"body":{"token":"t"}}}`,
			want:   `{"response":{"status":200,"headers":{"Set-Cookie":["****","****"]},"body":{"token":"****"}}}`,
			counts: Counts{"auth-headers": 2, "secret-fields": 1},
		},
		{
			name:   "header given as an array (line 33)",
			in:     `{"headers":{"X-Forwarded-For":["10.0.0.1","10.0.0.2"],"Authorization":["Bearer abc.def.ghi"]}}`,
			want:   `{"headers":{"X-Forwarded-For":["10.0.0.1","10.0.0.2"],"Authorization":["Bearer ****"]}}`,
			counts: Counts{"auth-headers": 1},
		},
		{
			name:   "digest auth (line 34)",
			in:     `{"headers":{"Authorization":"Digest username=\"mufasa\", realm=\"x\", response=\"6629fae49393a05397450978507c4ef1\""}}`,
			want:   `{"headers":{"Authorization":"Digest ****"}}`,
			counts: Counts{"auth-headers": 1},
		},
		{
			name:   "already redacted header is not counted (line 12)",
			in:     `{"headers":{"Authorization":"Bearer ****"}}`,
			want:   `{"headers":{"Authorization":"Bearer ****"}}`,
			counts: Counts{},
		},
		{
			name:   "secret fields, card fields and cvv in the body (line 1)",
			in:     `{"body":{"user":{"email":"a@b.com","card":{"number":"4111111111111111","cvv":"123"}},"card_number":"378282246310005"}}`,
			want:   `{"body":{"user":{"email":"` + h("a@b.com") + `","card":{"number":"************1111"}},"card_number":"***********0005"}}`,
			counts: Counts{"email": 1, "credit-card": 1, "cvv-fields": 1, "card-number-fields": 1},
		},
		{
			name:   "key names in any spelling (line 27)",
			in:     `{"body":{"Password":"a","PASSWORD":"b","ApiKey":"c","api-key":"d","X-API-Key":"e","Client_Secret":"f"}}`,
			want:   `{"body":{"Password":"****","PASSWORD":"****","ApiKey":"` + h("c") + `","api-key":"` + h("d") + `","X-API-Key":"` + h("e") + `","Client_Secret":"****"}}`,
			counts: Counts{"secret-fields": 3, "api-key-names": 3},
		},
		{
			name:   "look-alike keys are left alone (line 48)",
			in:     `{"body":{"password_hint":"first pet","passwordless":true,"tokenizer":"bpe","secret_santa":"Ann"}}`,
			want:   `{"body":{"password_hint":"first pet","passwordless":true,"tokenizer":"bpe","secret_santa":"Ann"}}`,
			counts: Counts{},
		},
		{
			name:   "empty and non-string values under secret keys (line 13)",
			in:     `{"body":{"password":null,"secret":"","api_key":0,"token":false,"pwd":[],"email":null,"card_number":""}}`,
			want:   `{"body":{"password":null,"secret":"","api_key":"` + h("0") + `","token":"****","pwd":[],"email":null,"card_number":""}}`,
			counts: Counts{"api-key-names": 1, "secret-fields": 1},
		},
		{
			name:   "key rule applies to every value inside an object",
			in:     `{"body":{"password":{"old":"a","new":"b","tries":3,"note":null}}}`,
			want:   `{"body":{"password":{"old":"****","new":"****","tries":"****","note":null}}}`,
			counts: Counts{"secret-fields": 3},
		},
		{
			name:   "numbers: cards are redacted, everything else kept as written (line 28)",
			in:     `{"body":{"card_number":4111111111111111,"order_id":12345678901234567890,"amount":10.50,"ratio":1.0,"exp":1e3,"note":"Tom & Jerry <tom@example.com>"}}`,
			want:   `{"body":{"card_number":"************1111","order_id":12345678901234567890,"amount":10.50,"ratio":1.0,"exp":1e3,"note":"Tom & Jerry <` + h("tom@example.com") + `>"}}`,
			counts: Counts{"card-number-fields": 1, "email": 1},
		},
		{
			name:   "card number as a JSON number under any key",
			in:     `{"body":{"ref":4111111111111111,"ts_us":1705312800123456,"neg":-5}}`,
			want:   `{"body":{"ref":"************1111","ts_us":1705312800123456,"neg":-5}}`,
			counts: Counts{"credit-card": 1},
		},
		{
			name:   "duplicate keys are both redacted (line 25)",
			in:     `{"body":{"email":"first@example.com","email":"second@example.com"}}`,
			want:   `{"body":{"email":"` + h("first@example.com") + `","email":"` + h("second@example.com") + `"}}`,
			counts: Counts{"email": 2},
		},
		{
			name:   "deeply nested arrays (line 3)",
			in:     `{"body":{"orders":[{"items":[{"buyer":{"email":"alice@example.com"}}]},{"items":[]},{"items":[[{"deep":["carol@example.net"]}]]}]}}`,
			want:   `{"body":{"orders":[{"items":[{"buyer":{"email":"` + h("alice@example.com") + `"}}]},{"items":[]},{"items":[[{"deep":["` + h("carol@example.net") + `"]}]]}]}}`,
			counts: Counts{"email": 2},
		},
		{
			name:   "removed key in an array of objects (line 26)",
			in:     `{"body":{"users":[{"name":"u1","cvv":"1"},{"name":"u2","cvv":"2"},{"name":"u3"}]}}`,
			want:   `{"body":{"users":[{"name":"u1"},{"name":"u2"},{"name":"u3"}]}}`,
			counts: Counts{"cvv-fields": 2},
		},
		{
			name:   "escaped characters are decoded before matching (line 45)",
			in:     `{"body":{"contact":"alice@example.com","card":"4111111111111111"}}`,
			want:   `{"body":{"contact":"` + h("alice@example.com") + `","card":"************1111"}}`,
			counts: Counts{"email": 1, "credit-card": 1},
		},
		{
			name:   "value rules also apply outside headers and body",
			in:     `{"ts":"2025-01-15T10:00:00Z","path":"/v1/users/a@b.com","method":"GET"}`,
			want:   `{"ts":"2025-01-15T10:00:00Z","path":"/v1/users/` + h("a@b.com") + `","method":"GET"}`,
			counts: Counts{"email": 1},
		},
		{
			// Outside headers, every JSON field gets the body rules, even at
			// the top level where the transaction has no such field.
			name:   "body rules apply to top-level fields",
			in:     `{"password":"x","api_key":"k"}`,
			want:   `{"password":"****","api_key":"` + h("k") + `"}`,
			counts: Counts{"secret-fields": 1, "api-key-names": 1},
		},
		{
			name:   "unexpected top-level field with nested secrets",
			in:     `{"ts":"t","method":"POST","user":{"password":"Summer2024","cvv":"123","note":"a@b.com"}}`,
			want:   `{"ts":"t","method":"POST","user":{"password":"****","note":"` + h("a@b.com") + `"}}`,
			counts: Counts{"secret-fields": 1, "cvv-fields": 1, "email": 1},
		},
		{
			name:   "unexpected field inside the response",
			in:     `{"response":{"status":200,"session":{"token":"t1"}}}`,
			want:   `{"response":{"status":200,"session":{"token":"****"}}}`,
			counts: Counts{"secret-fields": 1},
		},
		{
			// Header rules stay with headers: a JSON field called Cookie is
			// not an HTTP header.
			name:   "header rules do not apply to top-level fields",
			in:     `{"Cookie":"plain value"}`,
			want:   `{"Cookie":"plain value"}`,
			counts: Counts{},
		},
		{
			name:   "headers that are not an object are still scanned",
			in:     `{"headers":"Authorization: Bearer x a@b.com"}`,
			want:   `{"headers":"Authorization: Bearer x ` + h("a@b.com") + `"}`,
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
		})
	}
}

func TestPreserveScheme(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct {
		in, want string
	}{
		{"Bearer abc", "Bearer ****"},
		{"bearer abc", "bearer ****"},
		{"Basic dXNlcjpwYXNz", "Basic ****"},
		{"Negotiate YIIabc", "Negotiate ****"},
		{"Bearer    spaced", "Bearer ****"},
		{"Bearer ****", "Bearer ****"},
		{"Bearer", "****"},         // no credential: mask it all
		{"Bearer ", "****"},        // same
		{"Foo bar", "****"},        // unknown scheme: not kept
		{"my secret pass", "****"}, // first word is not a scheme
		{"session=abc123", "****"},
	}
	for _, tt := range tests {
		in := `{"headers":{"Authorization":"` + tt.in + `"}}`
		want := `{"headers":{"Authorization":"` + tt.want + `"}}`
		if got, _ := redactLine(t, e, in); got != want {
			t.Errorf("Authorization %q: got %s, want %s", tt.in, got, want)
		}
	}
}

func TestRedactLineNotAnObject(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct {
		in, want string
	}{
		{`42`, `42`},
		{`["a@b.com","4111111111111111"]`, `["` + Hash("a@b.com") + `","************1111"]`},
		{`"mail a@b.com"`, `"mail ` + Hash("a@b.com") + `"`},
		{`null`, `null`},
	}
	for _, tt := range tests {
		out, notice, err := e.RedactLine([]byte(tt.in), nil)
		if err != nil {
			t.Fatalf("RedactLine(%s): %v", tt.in, err)
		}
		if string(out) != tt.want {
			t.Errorf("RedactLine(%s) = %s, want %s", tt.in, out, tt.want)
		}
		if notice != NoticeNotObject {
			t.Errorf("RedactLine(%s) notice = %q, want %q", tt.in, notice, NoticeNotObject)
		}
	}
}

// A line that is not an object has no known structure, so every key rule
// applies, header rules included.
func TestRedactLineNotAnObjectUsesAllRules(t *testing.T) {
	e := shippedEngine(t)
	in := `[{"Authorization":"Bearer abc123","password":"x"},"{\"Cookie\":\"s=1\"}"]`
	want := `[{"Authorization":"Bearer ****","password":"****"},"{\"Cookie\":\"****\"}"]`
	counts := Counts{}
	out, notice, err := e.RedactLine([]byte(in), counts)
	if err != nil || notice != NoticeNotObject {
		t.Fatalf("err %v, notice %q", err, notice)
	}
	if string(out) != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}
	// credential-headers comes before secret-fields in rules.yaml, so it is
	// the rule that catches "password" here.
	if !maps.Equal(counts, Counts{"auth-headers": 2, "credential-headers": 1}) {
		t.Errorf("counts = %v", counts)
	}
}

func TestRedactLineErrors(t *testing.T) {
	e := shippedEngine(t)
	for _, tt := range []struct {
		in   string
		want error
	}{
		{``, ErrEmpty},
		{`{"body":{"email":"trunc@exam`, ErrInvalidJSON},
		{strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1), ErrTooDeep},
	} {
		out, _, err := e.RedactLine([]byte(tt.in), nil)
		if !errors.Is(err, tt.want) || out != nil {
			t.Errorf("RedactLine(%.30s) = (%q, %v), want (nil, %v)", tt.in, out, err, tt.want)
		}
	}
}

// Every line of the sample input: no panic, errors only where the line is
// broken, and running the engine on its own output changes nothing.
func TestRedactLineSampleInput(t *testing.T) {
	data, err := os.ReadFile("../../input.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	e := shippedEngine(t)

	wantErr := map[int]error{19: ErrEmpty, 20: ErrInvalidJSON, 21: ErrInvalidJSON, 22: ErrEmpty, 50: ErrInvalidJSON}
	wantNotice := map[int]bool{23: true, 24: true}

	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != 50 {
		t.Fatalf("input has %d lines, want 50", len(lines))
	}
	for i, line := range lines {
		n := i + 1
		out, notice, err := e.RedactLine(line, nil)
		if !errors.Is(err, wantErr[n]) {
			t.Errorf("line %d: error = %v, want %v", n, err, wantErr[n])
			continue
		}
		if err != nil {
			continue
		}
		if (notice != "") != wantNotice[n] {
			t.Errorf("line %d: notice = %q", n, notice)
		}
		counts := Counts{}
		again, _, err := e.RedactLine(out, counts)
		if err != nil {
			t.Errorf("line %d: output does not parse: %v", n, err)
			continue
		}
		if !bytes.Equal(again, out) || len(counts) != 0 {
			t.Errorf("line %d: not idempotent (second run counted %v)\n once %s\ntwice %s", n, counts, out, again)
		}
	}
}
