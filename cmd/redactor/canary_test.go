package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the expected output files in testdata/")

// TestNoSecretLeaks is the most important test: every sensitive value in the
// sample input is listed here, and none of them may appear in stdout or
// stderr. For card numbers the last 4 digits are allowed (that is what
// "partial" keeps), so only longer pieces are listed.
func TestNoSecretLeaks(t *testing.T) {
	_, stdout, stderr := runCLI(t, "", "--rules", rulesFile, inputFile)

	secrets := []string{
		// Emails (including the percent-encoded and escaped forms).
		"a@b.com", "jane.doe+billing@example.co.uk", "alice@example.com", "bob@example.org",
		"carol@example.net", "tanaka@example.co.jp", "bob@example.com", "bob%40example.com",
		"dave@example.com", "carol@example.com", "erin@example.com", "first@example.com",
		"second@example.com", "tom@example.com", "john.doe+tag@sub.example.co.uk",
		"UPPER@EXAMPLE.COM", "gina@example.com", "gina%40example.com", "hank@example.com",
		"deep@example.com", "a1@x.com", "a2@x.com", "a3@x.com", "a4@x.com", "a5@x.com",
		"ivan@example.com", "zed@example.com", "user@example.com", "trunc@exam",

		// Card numbers, in every format they appear in. Full numbers for
		// the unbroken ones: the input also has 4111111111111112, an order
		// reference that fails Luhn and is rightly kept.
		"4111111111111111", "378282246310005", "5555555555554444", "4012888888881881",
		"30569309025904", "6011111111111117",
		"4111 1111 1111", "3782 822463", "5555-5555-5555", "5555 5555 5555",

		// JWTs: every segment and the pieces around "_" and "-".
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIi", "eyJhIjoiPz8", "In0",
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV", "adQssw5c", "dBjftJeZ4CVP", "mB92K27uhbUJU1p1r", "wW1gFWFOEjXk",
		"abc.def.ghi",

		// API keys, passwords, tokens, cookies, HTTP credentials.
		"sk_live_abc123", "sk_live_9fA2kLmQ7x", "sk_live_Zz91Qw2Lm", "demo_key_1", "demo_key_2",
		"hunter2", "p@ssw0rd!", "deepsecret", "abc123", "abc123def456", "csrf=zzz",
		"dXNlcjpwYXNz", "mufasa", "6629fae49393a05397450978507c4ef1",

		// Personal data.
		"123-45-6789", "555-0132", "1990-04-12",
	}
	for _, s := range secrets {
		if strings.Contains(stdout, s) {
			t.Errorf("stdout contains %q", s)
		}
		if strings.Contains(stderr, s) {
			t.Errorf("stderr contains %q", s)
		}
	}
	if strings.Contains(stdout, `"cvv"`) {
		t.Error(`stdout still has a "cvv" key`)
	}
}

// TestExpectedOutput compares a full run on input.ndjson with the reviewed
// output in testdata/. After an intended change, regenerate with
//
//	go test ./cmd/redactor -run TestExpectedOutput -update
//
// and review the diff line by line before committing it.
func TestExpectedOutput(t *testing.T) {
	code, stdout, stderr := runCLI(t, "", "--rules", rulesFile, inputFile)
	if code != exitOK {
		t.Fatalf("exit code %d", code)
	}
	compareGolden(t, "testdata/expected_output.ndjson", stdout)
	compareGolden(t, "testdata/expected_stderr.txt", stderr)
}

func compareGolden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got != string(want) {
		gotLines, wantLines := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
			var g, w string
			if i < len(gotLines) {
				g = gotLines[i]
			}
			if i < len(wantLines) {
				w = wantLines[i]
			}
			if g != w {
				t.Errorf("%s line %d differs:\n got %s\nwant %s", path, i+1, g, w)
				return
			}
		}
	}
}

// TestNoLeaksInHardCases runs the cases found by a second, adversarial review
// of the rules, end to end through the CLI. Each line hides secrets in a
// place the first version of the rules missed.
func TestNoLeaksInHardCases(t *testing.T) {
	lines := []string{
		// camelCase and other spellings of secret field names
		`{"body":{"accessToken":"opaque-AT-111","refreshToken":"opaque-RT-222","clientSecret":"cs-333","apiSecret":"as-444","privateKey":"pk-555","authToken":"tok-666","sessionToken":"st-777"}}`,
		// credential headers that are not in the auth-headers list
		`{"headers":{"X-Access-Token":"hdr-AT-888","X-CSRF-Token":"csrf-999","X-Amz-Security-Token":"amz-000","X-Session-Id":"sid-121"}}`,
		// a URL in a field, a session in a Referer header
		`{"body":{"url":"https://x.example/cb?token=url-tok-343&state=1"},"headers":{"Referer":"https://x.example/?session=ref-sess-454"}}`,
		// XML and multipart bodies
		`{"body":"<login><password>xml-pw-565</password></login>","headers":{"Content-Type":"application/xml"}}`,
		`{"body":"--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nmultipart-pw-676\r\n--b--"}`,
		// camelCase names in free text, an encoded email in text
		`{"body":{"note":"accessToken=txt-AT-787 and clientSecret: txt-cs-898, contact enc%40example.com"}}`,
		// a top-level field that is not part of the transaction
		`{"user":{"password":"top-pw-909"}}`,
	}
	_, stdout, stderr := runCLI(t, strings.Join(lines, "\n")+"\n", "--rules", rulesFile)

	for _, secret := range []string{
		"opaque-AT-111", "opaque-RT-222", "cs-333", "as-444", "pk-555", "tok-666", "st-777",
		"hdr-AT-888", "csrf-999", "amz-000", "sid-121", "url-tok-343", "ref-sess-454",
		"xml-pw-565", "multipart-pw-676", "txt-AT-787", "txt-cs-898", "enc%40example.com", "top-pw-909",
	} {
		if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
			t.Errorf("%q leaked", secret)
		}
	}
}
