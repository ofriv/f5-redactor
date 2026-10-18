package redact

import (
	"strings"
	"testing"
)

// Secrets with a well-known shape, and secrets in places found in the third
// review round: URLs with a password, PEM keys, raw HTTP requests in text.
func TestKnownSecretFormats(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct{ name, in, want string }{
		{"github token", "t ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 end", "t **** end"},
		{"github fine-grained token", "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789", "****"},
		{"gitlab token", "glpat-abcdefghij0123456789", "****"},
		{"slack token", "xoxb-1234567890-0987654321-abcdefghij", "****"},
		{"google api key", "key=AIza" + strings.Repeat("x", 35), "key=****"},
		{"aws access key id", "AKIAIOSFODNN7EXAMPLE", "****"},
		{"stripe restricted key", "rk_live_51Habc", "****"},
		{"too short to be a github token", "ghp_short", "ghp_short"},

		{"password in a url", "postgres://admin:hunter2@localhost:5432/app", "postgres://admin:****@localhost:5432/app"},
		{"url without a password", "https://example.org/x?a=1", "https://example.org/x?a=1"},

		{"pem private key", "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\nabc\n-----END RSA PRIVATE KEY-----\nb", "a\n****\nb"},
		{"pem public key is not a secret", "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"},

		{"raw http request", "GET / HTTP/1.1\r\nAuthorization: Bearer opaque123\r\nCookie: sid=s1; theme=dark\r\nHost: x\r\n", "GET / HTTP/1.1\r\nAuthorization: Bearer ****\r\nCookie: ****\r\nHost: x\r\n"},
		{"authorization in a log line", "proxy-authorization: Basic dXNlcjpwYXNz", "proxy-authorization: Basic ****"},

		{"quoted value with spaces", `cfg password: "my secret pass" done`, `cfg password: "****" done`},
		{"single-quoted value", `cfg token='abc 123' done`, `cfg token='****' done`},
		{"bearer_token in text", "bearer_token=abc", "bearer_token=****"},
		{"escaped json text", `{\"password\":\"hunter2\"}`, `{\"password\":\"****\"}`},
		{"international email", "mail user@exämple.com", "mail " + Hash("user@exämple.com")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.RedactText(tt.in, nil)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
			if again := e.RedactText(got, nil); again != got {
				t.Errorf("not idempotent: %q", again)
			}
		})
	}
}

func TestKeyNamesWithSpacesAndNewHeaders(t *testing.T) {
	e := shippedEngine(t)
	in := `{"body":{"password ":"a"," token":"b"},"headers":{"X-Goog-Api-Key":"c","X-Pwd":"d","X-Api-Key":"k"}}`
	want := `{"body":{"password ":"****"," token":"****"},"headers":{"X-Goog-Api-Key":"****","X-Pwd":"****","X-Api-Key":"` + Hash("k") + `"}}`
	if got, _ := redactLine(t, e, in); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
