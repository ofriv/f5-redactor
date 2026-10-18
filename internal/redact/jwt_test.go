package redact

import (
	"strings"
	"testing"
)

// Regression tests for the reported issue: "the provided rules.yaml misses
// some JWTs seen in production samples".
//
// Cause: the jwt pattern used the standard base64 alphabet
// [A-Za-z0-9+/=]. JWTs are base64url (RFC 7515), which uses "-" and "_".
// A token with "_" or "-" in its payload was not matched at all (lines 11
// and 16), and a token with "_" only in its signature was matched up to the
// "_", leaving the rest of the signature in the output (line 15:
// "****_adQssw5c"). That second case is a partial leak, not just a miss.

// The two tokens that appear in input.ndjson, and the parts of each that
// must never reach the output.
const (
	jwtJohnDoe = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	jwtShort   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiPz8_In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// jwtFragments returns pieces of a token that must not appear in output:
// every segment, and the parts of a segment on either side of "_" or "-".
func jwtFragments(token string) []string {
	var out []string
	for _, seg := range strings.Split(token, ".") {
		out = append(out, seg)
		for _, part := range strings.FieldsFunc(seg, func(r rune) bool { return r == '_' || r == '-' }) {
			if len(part) >= 6 {
				out = append(out, part)
			}
		}
	}
	return out
}

func TestJWTNeverLeaks(t *testing.T) {
	e := shippedEngine(t)
	lines := map[string]string{
		"line 15: id_token field":               `{"body":{"id_token":"` + jwtJohnDoe + `"}}`,
		"line 15: bearer token in a note":       `{"body":{"note":"forwarded header was Bearer ` + jwtJohnDoe + `"}}`,
		"line 16: token in a sentence":          `{"body":{"msg":"session ` + jwtShort + ` expired, retry"}}`,
		"line 11: access_token in JSON":         `{"response":{"body":"{\"access_token\":\"` + jwtShort + `\",\"expires_in\":3600}"}}`,
		"token in a query string":               `{"path":"/cb?state=1&jwt=` + jwtShort + `"}`,
		"token in a header we have no rule for": `{"headers":{"X-Session":"` + jwtShort + `"}}`,
	}
	for name, line := range lines {
		t.Run(name, func(t *testing.T) {
			out, _ := redactLine(t, e, line)
			for _, token := range []string{jwtJohnDoe, jwtShort} {
				for _, frag := range jwtFragments(token) {
					if strings.Contains(out, frag) {
						t.Errorf("output contains JWT fragment %q:\n%s", frag, out)
					}
				}
			}
		})
	}
}

func TestJWTPattern(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"base64url with _ and -", "t " + jwtShort + " end", "t **** end"},
		{"underscore only in the signature", "t " + jwtJohnDoe, "t ****"},
		{"token in a url path keeps the rest of the path", "/v1/" + jwtShort + "/users/42/orders", "/v1/****/users/42/orders"},
		{"padded segments", "t eyJhbGciOiJIUzI1NiJ9.eyJhIjoiYiJ9==.c2ln end", "t **** end"},
		// alg "none": the signature is empty. The trailing dot stays, which
		// leaks nothing.
		{"unsigned token", "t eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0. end", "t ****. end"},
		// JWE (encrypted) tokens have five parts; all of them are masked.
		{"five-part JWE", "t eyJhbGciOiJSU0EtT0FFUCJ9.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ end", "t **** end"},
		{"not a JWT: one segment", "eyJhbGciOiJIUzI1NiJ9 alone", "eyJhbGciOiJIUzI1NiJ9 alone"},
		{"not a JWT: no eyJ prefix", "abc.def.ghi", "abc.def.ghi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.RedactText(tt.in, nil); got != tt.want {
				t.Errorf("RedactText(%.60q...)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

// Fields that commonly hold tokens are masked by name, so a token is hidden
// even when it is not a JWT (e.g. an opaque OAuth token).
func TestTokenFieldNames(t *testing.T) {
	e := shippedEngine(t)
	in := `{"body":{"access_token":"opaque123","refresh_token":"r456","id_token":"i789","token_type":"Bearer"}}`
	want := `{"body":{"access_token":"****","refresh_token":"****","id_token":"****","token_type":"Bearer"}}`
	if got, _ := redactLine(t, e, in); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
