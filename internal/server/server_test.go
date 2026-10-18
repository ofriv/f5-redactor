package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"f5-redactor/internal/config"
	"f5-redactor/internal/redact"
)

func newTestServer(t *testing.T, opts Options) (*Server, *httptest.Server) {
	t.Helper()
	cfg, err := config.Load("../../rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := New(redact.New(cfg), opts)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url+"/redact", "application/x-ndjson", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// The service must produce exactly what the CLI produces for the sample.
func TestRedactSampleInput(t *testing.T) {
	_, ts := newTestServer(t, Options{})
	input, err := os.ReadFile("../../input.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../cmd/redactor/testdata/expected_output.ndjson")
	if err != nil {
		t.Fatal(err)
	}

	resp := post(t, ts.URL, string(input))
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Errorf("status %d, content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !bytes.Equal(got, want) {
		t.Errorf("response differs from the CLI's expected output")
	}

	// The summary arrives as a trailer, after the body.
	var summary struct {
		LinesRead  int            `json:"lines_read"`
		Rejected   map[string]int `json:"rejected"`
		Redactions map[string]int `json:"redactions"`
		Error      string         `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp.Trailer.Get(summaryTrailer)), &summary); err != nil {
		t.Fatalf("summary trailer %q: %v", resp.Trailer.Get(summaryTrailer), err)
	}
	if summary.LinesRead != 50 || summary.Rejected["invalid_json"] != 3 || summary.Redactions["email"] != 31 || summary.Error != "" {
		t.Errorf("summary = %+v", summary)
	}
}

// True streaming: the client sends one line and reads its redacted version
// back before sending the next one. A server that buffered the request (or
// the response) would deadlock here, so the test has a timeout.
func TestRedactStreamsLineByLine(t *testing.T) {
	_, ts := newTestServer(t, Options{})

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/redact", pr)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		respc := make(chan *http.Response, 1)
		go func() {
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				close(respc)
				return
			}
			respc <- resp
		}()

		if _, err := io.WriteString(pw, `{"body":{"password":"one"}}`+"\n"); err != nil {
			t.Error(err)
			return
		}
		resp, ok := <-respc
		if !ok {
			return
		}
		defer resp.Body.Close()
		r := bufio.NewReader(resp.Body)

		for i, want := range []string{`{"body":{"password":"****"}}`, `{"body":{"token":"****"}}`} {
			if i == 1 {
				if _, err := io.WriteString(pw, `{"body":{"token":"two"}}`+"\n"); err != nil {
					t.Error(err)
					return
				}
			}
			line, err := r.ReadString('\n')
			if err != nil {
				t.Errorf("line %d: %v", i+1, err)
				return
			}
			if strings.TrimSuffix(line, "\n") != want {
				t.Errorf("line %d = %q, want %q", i+1, line, want)
			}
		}
		pw.Close()
		if rest, _ := io.ReadAll(r); len(rest) != 0 {
			t.Errorf("unexpected trailing output %q", rest)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		pw.CloseWithError(io.ErrUnexpectedEOF)
		t.Fatal("timed out: the response was not streamed line by line")
	}
}

func TestRedactBrokenLines(t *testing.T) {
	_, ts := newTestServer(t, Options{MaxLineBytes: 40})
	body := "{\"body\":{\"email\":\"trunc@exam\n" +
		`{"body":{"note":"` + strings.Repeat("x", 100) + `"}}` + "\n" +
		`{"ok":true}` + "\n"
	resp := post(t, ts.URL, body)
	got, _ := io.ReadAll(resp.Body)
	want := `{"_redactor":{"error":"invalid_json","line":1}}` + "\n" +
		`{"_redactor":{"error":"line_too_long","line":2}}` + "\n" +
		`{"ok":true}` + "\n"
	if string(got) != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestRedactOnlyAcceptsPost(t *testing.T) {
	_, ts := newTestServer(t, Options{})
	resp, err := http.Get(ts.URL + "/redact")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /redact: status %d, want 405", resp.StatusCode)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	s, ts := newTestServer(t, Options{})
	status := func(path string) int {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := status("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz = %d", got)
	}
	if got := status("/readyz"); got != http.StatusOK {
		t.Errorf("/readyz = %d", got)
	}

	s.SetReady(false) // shutting down
	if got := status("/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("/readyz while shutting down = %d, want 503", got)
	}
	if got := status("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz while shutting down = %d, want 200 (the process is still alive)", got)
	}
}

// Requests over the limit are turned away at once instead of piling up.
func TestConcurrencyLimit(t *testing.T) {
	_, ts := newTestServer(t, Options{MaxConcurrent: 1})

	// Hold the only slot with a request whose body stays open.
	pr, pw := io.Pipe()
	defer pw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/redact", pr)
	held := make(chan *http.Response, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			held <- resp
		}
	}()
	if _, err := io.WriteString(pw, "{}\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-held:
		defer resp.Body.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not start")
	}

	resp := post(t, ts.URL, "{}\n")
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Errorf("second request: status %d, Retry-After %q; want 503 with Retry-After", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

// The request log has counts only, never request content.
func TestLogHasNoInputData(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	_, ts := newTestServer(t, Options{Logger: logger})

	resp := post(t, ts.URL, `{"body":{"password":"hunter2","note":"a@b.com"}}`+"\nnot json sk_live_abc123\n")
	_, _ = io.ReadAll(resp.Body)

	if !strings.Contains(logs.String(), `"msg":"redact request"`) || !strings.Contains(logs.String(), `"lines_read":2`) {
		t.Errorf("missing request log: %s", logs.String())
	}
	for _, secret := range []string{"hunter2", "a@b.com", "sk_live_abc123", "not json"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log contains %q: %s", secret, logs.String())
		}
	}
}

// A client that sends part of a line and then stalls is cut off after the
// idle timeout, and its slot goes to the next client.
func TestStalledClientIsCutOff(t *testing.T) {
	_, ts := newTestServer(t, Options{MaxConcurrent: 1, IdleTimeout: 300 * time.Millisecond})

	pr, pw := io.Pipe()
	defer pw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/redact", pr)
	stalled := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, err = io.ReadAll(resp.Body) // returns once the server gives up
			resp.Body.Close()
		}
		stalled <- err
	}()
	if _, err := io.WriteString(pw, `{"body":{"pass`); err != nil { // half a line, then nothing
		t.Fatal(err)
	}

	select {
	case <-stalled:
	case <-time.After(5 * time.Second):
		t.Fatal("stalled request was not cut off")
	}

	// The slot is free again.
	resp := post(t, ts.URL, `{"body":{"password":"x"}}`+"\n")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != `{"body":{"password":"****"}}`+"\n" {
		t.Errorf("after the stalled client: status %d, body %q", resp.StatusCode, body)
	}
}

// A steady stream that takes longer than the idle timeout in total is not
// cut off: the deadline moves with every line.
func TestSlowSteadyStreamIsNotCutOff(t *testing.T) {
	_, ts := newTestServer(t, Options{IdleTimeout: 300 * time.Millisecond})

	pr, pw := io.Pipe()
	go func() {
		for range 6 { // ~600ms in total, 100ms between lines
			io.WriteString(pw, `{"body":{"token":"t"}}`+"\n")
			time.Sleep(100 * time.Millisecond)
		}
		pw.Close()
	}()
	resp, err := http.Post(ts.URL+"/redact", "application/x-ndjson", pr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := strings.Count(string(body), `{"body":{"token":"****"}}`); got != 6 {
		t.Errorf("got %d of 6 lines: %q", got, body)
	}
}
