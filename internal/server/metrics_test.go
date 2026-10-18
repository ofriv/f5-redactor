package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"f5-redactor/internal/config"
	"f5-redactor/internal/redact"
)

func getMetrics(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("GET /metrics: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	return string(body)
}

func TestMetricsCountRequests(t *testing.T) {
	_, ts := newTestServer(t, Options{})
	input, err := os.ReadFile("../../input.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	resp := post(t, ts.URL, string(input))
	_, _ = io.Copy(io.Discard, resp.Body)

	got := getMetrics(t, ts.URL)
	for _, want := range []string{
		`redactor_requests_total{result="ok"} 1`,
		`redactor_requests_total{result="busy"} 0`,
		"redactor_lines_read_total 50",
		`redactor_lines_rejected_total{reason="invalid_json"} 3`,
		`redactor_redactions_total{rule="email"} 31`,       // as in testdata/expected_stderr.txt
		`redactor_redactions_total{rule="bearer-token"} 0`, // listed though unused
		"redactor_request_duration_seconds_count 1",
		"redactor_requests_in_flight 0",
		"# TYPE redactor_redactions_total counter",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("metrics lack %q:\n%s", want, got)
		}
	}
	// Only rule names and fixed reasons, never input data.
	if strings.Contains(got, "@") {
		t.Errorf("metrics contain input data:\n%s", got)
	}
}

func TestReload(t *testing.T) {
	s, ts := newTestServer(t, Options{})
	line := `{"body":{"note":"mail a@b.com"}}` + "\n"
	redactOnce := func() string {
		resp := post(t, ts.URL, line)
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	before := redactOnce()

	// Rules that do not load: the current rules stay.
	if err := s.Reload(func() (*redact.Engine, error) { return nil, errors.New("bad rules") }); err == nil {
		t.Fatal("Reload with failing rules returned nil")
	}
	if got := redactOnce(); got != before {
		t.Errorf("after a failed reload got %s, want %s", got, before)
	}

	// New rules: emails are masked instead of hashed.
	cfg, err := config.Parse([]byte("version: 1\nvalue_rules:\n  - { name: mail, pattern: '[a-z]+@[a-z.]+', action: mask }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(func() (*redact.Engine, error) { return redact.New(cfg), nil }); err != nil {
		t.Fatal(err)
	}
	if got, want := redactOnce(), `{"body":{"note":"mail ****"}}`+"\n"; got != want {
		t.Errorf("after reload got %s, want %s", got, want)
	}

	m := getMetrics(t, ts.URL)
	for _, want := range []string{`redactor_rules_reloads_total{result="ok"} 1`, `redactor_rules_reloads_total{result="failed"} 1`, `redactor_redactions_total{rule="mail"} 1`} {
		if !strings.Contains(m, want+"\n") {
			t.Errorf("metrics lack %q:\n%s", want, m)
		}
	}
}
