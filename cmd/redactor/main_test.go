package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rulesFile = "../../rules.yaml"
const inputFile = "../../input.ndjson"

func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestCLISampleInput(t *testing.T) {
	code, stdout, stderr := runCLI(t, "", "--rules", rulesFile, inputFile)
	if code != exitOK {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr)
	}

	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 48 { // 50 lines, 2 of them empty
		t.Errorf("got %d output lines, want 48", len(lines))
	}
	for _, want := range []string{
		`{"_redactor":{"error":"invalid_json","line":20}}`,
		`{"_redactor":{"error":"invalid_json","line":21}}`,
		`{"_redactor":{"error":"invalid_json","line":50}}`,
	} {
		if !strings.Contains(stdout, want+"\n") {
			t.Errorf("missing error record %s", want)
		}
	}

	for _, want := range []string{
		"redactor: 50 lines read, 48 written, 3 rejected, 2 empty skipped",
		"redactor: line 20: invalid_json",
		"redactor: line 23: not_an_object (redacted)",
		"  email ",
		"  credit-card ",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%s", want, stderr)
		}
	}

	// The broken lines carry secrets; none of them may appear anywhere.
	for _, secret := range []string{"erin@example.com", "trunc@exam", "eyJzdWIi"} {
		if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
			t.Errorf("%q leaked", secret)
		}
	}
}

func TestCLIReadsStdin(t *testing.T) {
	for _, args := range [][]string{{"--rules", rulesFile}, {"--rules", rulesFile, "-"}} {
		code, stdout, _ := runCLI(t, `{"body":{"password":"x"}}`+"\n", args...)
		if code != exitOK || stdout != `{"body":{"password":"****"}}`+"\n" {
			t.Errorf("args %v: code %d, stdout %q", args, code, stdout)
		}
	}
}

func TestCLISummaryJSON(t *testing.T) {
	code, _, stderr := runCLI(t, `{"body":{"password":"x"}}`+"\n", "--rules", rulesFile, "--summary-format", "json")
	if code != exitOK || !strings.Contains(stderr, `"secret-fields":1`) || !strings.HasPrefix(stderr, `{"lines_read":1`) {
		t.Errorf("code %d, stderr %q", code, stderr)
	}
}

func TestCLICheckConfig(t *testing.T) {
	code, stdout, _ := runCLI(t, "", "--rules", rulesFile, "--check-config")
	if code != exitOK || !strings.Contains(stdout, "OK (7 key rules, 8 value rules)") {
		t.Errorf("code %d, stdout %q", code, stdout)
	}

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nkey_rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "", "--rules", bad, "--check-config")
	if code != exitUsage || !strings.Contains(stderr, "no rules defined") {
		t.Errorf("code %d, stderr %q", code, stderr)
	}
}

// With rules that cannot be loaded, nothing is written: the input never
// passes through unredacted.
func TestCLIBadRulesWritesNothing(t *testing.T) {
	code, stdout, stderr := runCLI(t, `{"body":{"password":"x"}}`+"\n", "--rules", "missing.yaml")
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, "missing.yaml") {
		t.Errorf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestCLIUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"two input files", []string{"--rules", rulesFile, "a", "b"}, "at most one input file"},
		{"unknown flag", []string{"--nope"}, "flag provided but not defined"},
		{"bad summary format", []string{"--rules", rulesFile, "--summary-format", "xml"}, "text or json"},
		{"bad max line", []string{"--rules", rulesFile, "--max-line-bytes", "0"}, "must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, "", tt.args...)
			if code != exitUsage || !strings.Contains(stderr, tt.want) {
				t.Errorf("code %d, stderr %q", code, stderr)
			}
		})
	}
}

func TestCLIHelp(t *testing.T) {
	code, _, stderr := runCLI(t, "", "--help")
	if code != exitOK || !strings.Contains(stderr, "usage: redactor") {
		t.Errorf("code %d, stderr %q", code, stderr)
	}
}

func TestCLIMissingInputFile(t *testing.T) {
	code, _, stderr := runCLI(t, "", "--rules", rulesFile, "no-such-input.ndjson")
	if code != exitFailure || !strings.Contains(stderr, "no-such-input.ndjson") {
		t.Errorf("code %d, stderr %q", code, stderr)
	}
}

func TestCLIHashKey(t *testing.T) {
	in := `{"body":{"note":"a@b.com"}}` + "\n"

	t.Setenv(hashKeyEnv, "0123456789abcdef0123456789abcdef")
	code, stdout, _ := runCLI(t, in, "--rules", rulesFile)
	if code != exitOK || !strings.Contains(stdout, "hmac-sha256:") {
		t.Errorf("with a key: code %d, stdout %q", code, stdout)
	}

	t.Setenv(hashKeyEnv, "too-short")
	code, stdout, stderr := runCLI(t, in, "--rules", rulesFile)
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, "at least 32") || strings.Contains(stderr, "too-short") {
		t.Errorf("short key: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	t.Setenv(hashKeyEnv, "")
	code, stdout, _ = runCLI(t, in, "--rules", rulesFile)
	if code != exitOK || !strings.Contains(stdout, `"sha256:`) {
		t.Errorf("without a key: code %d, stdout %q", code, stdout)
	}
}
