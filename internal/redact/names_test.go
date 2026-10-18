package redact

import (
	"maps"
	"testing"
)

// Secret field names in every common spelling. JSON APIs mostly use
// camelCase, which the provided rules did not cover.
func TestSecretFieldSpellings(t *testing.T) {
	e := shippedEngine(t)
	for _, key := range []string{
		"access_token", "accessToken", "access-token", "AccessToken",
		"refreshToken", "idToken", "authToken", "sessionToken", "bearerToken",
		"clientSecret", "client-secret", "apiSecret", "privateKey", "private_key",
		"passphrase", "Password",
	} {
		in := `{"body":{"` + key + `":"s3cr3t-value"}}`
		want := `{"body":{"` + key + `":"****"}}`
		if got, _ := redactLine(t, e, in); got != want {
			t.Errorf("%s: got %s", key, got)
		}
	}
	// Names that end with a secret word, found by the independent reviews.
	for _, key := range []string{
		"newPassword", "current_password", "db_password", "secretAccessKey", "AWS_SECRET_ACCESS_KEY",
		"sessionId", "api_token", "csrf_token", "webhook_secret", "credentials", "authorization", "Cookie",
	} {
		in := `{"body":{"` + key + `":"s3cr3t-value"}}`
		want := `{"body":{"` + key + `":"****"}}`
		if got, _ := redactLine(t, e, in); got != want {
			t.Errorf("%s: got %s", key, got)
		}
	}
	// Look-alikes stay (input line 48 and similar): they do not END with a
	// secret word.
	for _, key := range []string{"password_hint", "passwordless", "tokenizer", "secret_santa", "token_type", "tokens_used", "session_count", "password_changed_at", "max_tokens", "author"} {
		in := `{"body":{"` + key + `":"v"}}`
		if got, _ := redactLine(t, e, in); got != in {
			t.Errorf("%s should not be redacted: %s", key, got)
		}
	}
}

func TestCredentialHeaders(t *testing.T) {
	e := shippedEngine(t)
	in := `{"headers":{"X-Access-Token":"a1","X-CSRF-Token":"c1","X-Amz-Security-Token":"z1","X-Session-Id":"s1","X-Client-Secret":"k1","X-Amz-Signature":"g1","Content-Type":"application/json","X-Request-Id":"r1"}}`
	want := `{"headers":{"X-Access-Token":"****","X-CSRF-Token":"****","X-Amz-Security-Token":"****","X-Session-Id":"****","X-Client-Secret":"****","X-Amz-Signature":"****","Content-Type":"application/json","X-Request-Id":"r1"}}`
	got, counts := redactLine(t, e, in)
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if !maps.Equal(counts, Counts{"credential-headers": 6}) {
		t.Errorf("counts = %v", counts)
	}
}

func TestSecretAssignmentSpellings(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct{ in, want string }{
		{"accessToken=abc1 next", "accessToken=**** next"},
		{"clientSecret: abc2", "clientSecret: ****"},
		// A cookie header written as text: the whole value is masked.
		{"Cookie: session=abc3; theme=dark", "Cookie: ****"},
		{"note session=abc3; theme=dark", "note session=****; theme=dark"},
		{"sessionId=abc4", "sessionId=****"},
		{"session expired, retry", "session expired, retry"},
	}
	for _, tt := range tests {
		if got := e.RedactText(tt.in, nil); got != tt.want {
			t.Errorf("RedactText(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
