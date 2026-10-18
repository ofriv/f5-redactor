package stream

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"f5-redactor/internal/config"
	"f5-redactor/internal/redact"
)

func testEngine(t testing.TB) *redact.Engine {
	t.Helper()
	cfg, err := config.Load("../../rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return redact.New(cfg)
}

func process(t *testing.T, in string, opts Options) (string, *Stats) {
	t.Helper()
	var out bytes.Buffer
	stats, err := Process(strings.NewReader(in), &out, testEngine(t), opts)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	return out.String(), stats
}

func TestProcessLineEndings(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"unix newlines", "{\"a\":1}\n{\"b\":2}\n", "{\"a\":1}\n{\"b\":2}\n"},
		{"windows newlines", "{\"a\":1}\r\n{\"b\":2}\r\n", "{\"a\":1}\n{\"b\":2}\n"},
		{"no newline at the end", "{\"a\":1}\n{\"b\":2}", "{\"a\":1}\n{\"b\":2}\n"},
		{"byte order mark", "\xEF\xBB\xBF{\"a\":1}\n", "{\"a\":1}\n"},
		{"empty input", "", ""},
		// Empty and whitespace-only lines are kept, one output line per
		// input line.
		{"only newlines", "\n\n\n", "\n\n\n"},
		{"whitespace lines", "  \n\t\n{\"a\":1}\n", "  \n\t\n{\"a\":1}\n"},
		{"empty line with windows ending", "{}\r\n\r\n{}\r\n", "{}\n\n{}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := process(t, tt.in, Options{})
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProcessRejectedLines(t *testing.T) {
	in := strings.Join([]string{
		`{"body":{"email":"a@b.com"}}`,
		``,
		`{"headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi`,
		`2025-01-15 10:00:20 WARN upstream timeout user=erin@example.com retry=3`,
		`42`,
	}, "\n") + "\n"

	var warnings bytes.Buffer
	got, stats := process(t, in, Options{Warnings: &warnings})

	want := `{"body":{"email":"` + redact.Hash("a@b.com") + `"}}` + "\n" +
		"\n" +
		`{"_redactor":{"error":"invalid_json","line":3}}` + "\n" +
		`{"_redactor":{"error":"invalid_json","line":4}}` + "\n" +
		`42` + "\n"
	if got != want {
		t.Errorf("output\n got %q\nwant %q", got, want)
	}

	if stats.LinesRead != 5 || stats.LinesWritten != 5 || stats.Empty != 1 ||
		stats.Rejected["invalid_json"] != 2 || stats.Notices[redact.NoticeNotObject] != 1 ||
		stats.Redactions["email"] != 1 {
		t.Errorf("stats = %+v", stats)
	}

	wantWarnings := "redactor: line 3: invalid_json\n" +
		"redactor: line 4: invalid_json\n" +
		"redactor: line 5: not_an_object (redacted)\n"
	if warnings.String() != wantWarnings {
		t.Errorf("warnings\n got %q\nwant %q", warnings.String(), wantWarnings)
	}

	// Nothing from the broken lines may reach the output or the warnings.
	for _, secret := range []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "erin@example.com", "a@b.com"} {
		if strings.Contains(got, secret) || strings.Contains(warnings.String(), secret) {
			t.Errorf("%q leaked", secret)
		}
	}
}

func TestProcessLongLines(t *testing.T) {
	const max = 32
	short := `{"a":"` + strings.Repeat("x", max-8) + `"}` // exactly max bytes
	if len(short) != max {
		t.Fatalf("test setup: short line is %d bytes", len(short))
	}
	long := `{"a":"` + strings.Repeat("y", 200_000) + `"}` // much longer than the 64 KiB read buffer
	in := short + "\n" + long + "\n" + short + "\r\n" + long

	got, stats := process(t, in, Options{MaxLineBytes: max})

	want := short + "\n" +
		`{"_redactor":{"error":"line_too_long","line":2}}` + "\n" +
		short + "\n" +
		`{"_redactor":{"error":"line_too_long","line":4}}` + "\n"
	if got != want {
		t.Errorf("output\n got %q\nwant %q", got, want)
	}
	if stats.Rejected["line_too_long"] != 2 {
		t.Errorf("rejected = %v", stats.Rejected)
	}
}

func TestProcessLineOneOverLimit(t *testing.T) {
	got, _ := process(t, `{"a":"xx"}`+"\n", Options{MaxLineBytes: 9})
	if want := `{"_redactor":{"error":"line_too_long","line":1}}` + "\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProcessWarningsAreCapped(t *testing.T) {
	in := strings.Repeat("not json\n", 10)
	var warnings bytes.Buffer
	_, stats := process(t, in, Options{Warnings: &warnings, MaxWarnings: 3})

	lines := strings.Split(strings.TrimSpace(warnings.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d warning lines, want 3 plus a notice:\n%s", len(lines), warnings.String())
	}
	if !strings.Contains(lines[3], "more than 3 warnings") {
		t.Errorf("last warning = %q", lines[3])
	}
	if stats.Rejected["invalid_json"] != 10 {
		t.Errorf("summary must still count every line: %v", stats.Rejected)
	}
}

// The output of a run, processed again, is unchanged, including the error
// records that replace broken lines.
func TestProcessIdempotent(t *testing.T) {
	in := "{\"body\":{\"password\":\"x\",\"note\":\"a@b.com\"}}\nbroken\n\n[1,2]\n"
	once, _ := process(t, in, Options{})
	twice, stats := process(t, once, Options{})
	if twice != once {
		t.Errorf("not idempotent\n once %q\ntwice %q", once, twice)
	}
	if len(stats.Redactions) != 0 {
		t.Errorf("second run redacted: %v", stats.Redactions)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestProcessWriteError(t *testing.T) {
	_, err := Process(strings.NewReader("{}\n"), failingWriter{}, testEngine(t), Options{})
	if err == nil || !strings.Contains(err.Error(), "write output") {
		t.Errorf("err = %v, want a write error", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestProcessReadError(t *testing.T) {
	_, err := Process(failingReader{}, io.Discard, testEngine(t), Options{})
	if err == nil || !strings.Contains(err.Error(), "read input") {
		t.Errorf("err = %v, want a read error", err)
	}
}

func TestProcessAfterLine(t *testing.T) {
	calls := 0
	_, err := Process(strings.NewReader("{}\n{}\n\n"), io.Discard, testEngine(t), Options{
		AfterLine: func() error { calls++; return nil },
	})
	if err != nil || calls != 3 {
		t.Errorf("err = %v, calls = %d, want nil and 3", err, calls)
	}

	_, err = Process(strings.NewReader("{}\n"), io.Discard, testEngine(t), Options{
		AfterLine: func() error { return errors.New("client went away") },
	})
	if err == nil {
		t.Error("an AfterLine error must stop processing")
	}
}

func TestSummaryText(t *testing.T) {
	stats := NewStats()
	stats.LinesRead, stats.LinesWritten, stats.Empty = 5, 4, 1
	stats.Rejected["invalid_json"] = 2
	stats.Notices["not_an_object"] = 1
	stats.Redactions["email"] = 3

	var buf bytes.Buffer
	if err := stats.WriteText(&buf, []string{"auth-headers", "email"}); err != nil {
		t.Fatal(err)
	}
	want := `redactor: 5 lines read, 4 written, 2 rejected, 1 empty
redactions by rule:
  auth-headers           0
  email                  3
rejected lines by reason:
  invalid_json           2
notices:
  not_an_object          1
`
	if buf.String() != want {
		t.Errorf("got\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestSummaryJSON(t *testing.T) {
	stats := NewStats()
	stats.LinesRead, stats.LinesWritten = 2, 2
	stats.Redactions["email"] = 3

	var buf bytes.Buffer
	if err := stats.WriteJSON(&buf, []string{"auth-headers", "email"}); err != nil {
		t.Fatal(err)
	}
	want := `{"lines_read":2,"lines_written":2,"empty_lines":0,"rejected":{},"notices":{},"redactions":{"auth-headers":0,"email":3}}` + "\n"
	if buf.String() != want {
		t.Errorf("got  %s\nwant %s", buf.String(), want)
	}
	if len(stats.Redactions) != 1 {
		t.Error("WriteJSON must not modify the stats")
	}
}

// oneLineReader returns one line per Read call, like a client that sends
// lines one at a time.
type oneLineReader struct{ lines []string }

func (r *oneLineReader) Read(p []byte) (int, error) {
	if len(r.lines) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.lines[0])
	r.lines = r.lines[1:]
	return n, nil
}

func TestProcessFlushesWhenInputIsIdle(t *testing.T) {
	eng := testEngine(t)

	// Lines arriving one by one: flush after each, so each reaches the
	// client before the next read blocks.
	flushes := 0
	_, err := Process(&oneLineReader{lines: []string{"{}\n", "{}\n", "{}\n"}}, io.Discard, eng, Options{
		Flush: func() error { flushes++; return nil },
	})
	if err != nil || flushes != 3 {
		t.Errorf("one line per read: err %v, flushes %d, want 3", err, flushes)
	}

	// A large upload already in the buffer: no flush until it runs out.
	flushes = 0
	_, err = Process(strings.NewReader(strings.Repeat("{}\n", 1000)), io.Discard, eng, Options{
		Flush: func() error { flushes++; return nil },
	})
	if err != nil || flushes != 1 {
		t.Errorf("buffered input: err %v, flushes %d, want 1", err, flushes)
	}

	// A partial line waiting in the buffer still triggers a flush: the next
	// read will block until the rest of it arrives.
	flushes = 0
	_, err = Process(&oneLineReader{lines: []string{"{}\n{\"a\"", ":1}\n"}}, io.Discard, eng, Options{
		Flush: func() error { flushes++; return nil },
	})
	if err != nil || flushes != 2 {
		t.Errorf("partial line buffered: err %v, flushes %d, want 2", err, flushes)
	}

	_, err = Process(strings.NewReader("{}\n"), io.Discard, eng, Options{
		Flush: func() error { return errors.New("client went away") },
	})
	if err == nil {
		t.Error("a Flush error must stop processing")
	}
}
