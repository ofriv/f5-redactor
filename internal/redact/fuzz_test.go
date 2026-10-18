package redact

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"f5-redactor/internal/config"
)

// Fuzz tests feed random inputs to the engine and check the properties that
// must hold for every input:
//
//   - no panic;
//   - the output of a line is valid JSON;
//   - running the engine on its own output changes nothing (idempotency).
//
// They run as normal tests over the seed inputs. To search for new failing
// inputs:
//
//	go test ./internal/redact -run '^$' -fuzz FuzzRedactLine -fuzztime 60s

func fuzzEngine(f *testing.F) *Engine {
	f.Helper()
	cfg, err := config.Load("../../rules.yaml")
	if err != nil {
		f.Fatal(err)
	}
	return New(cfg)
}

func FuzzRedactLine(f *testing.F) {
	data, err := os.ReadFile("../../input.ndjson")
	if err != nil {
		f.Fatal(err)
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		f.Add(line)
	}
	f.Add([]byte(`{"body":"{\"password\":\"x\",\"n\":\"[1,{\\\"cvv\\\":2}]\"}"}`))
	f.Add([]byte(`{"path":"/a?token=x&email=a%40b.com#frag","headers":{"Content-Type":"application/x-www-form-urlencoded"},"body":"a=1&password=2"}`))

	e := fuzzEngine(f)
	f.Fuzz(func(t *testing.T, line []byte) {
		out, _, err := e.RedactLine(line, nil)
		if err != nil {
			return
		}
		// encoding/json checks the output independently of my own parser.
		if !json.Valid(out) {
			t.Fatalf("output is not valid JSON\n in %q\nout %q", line, out)
		}
		again, _, err := e.RedactLine(out, nil)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not idempotent (err %v)\n   in %q\n once %q\ntwice %q", err, line, out, again)
		}
	})
}

func FuzzRedactText(f *testing.F) {
	for _, s := range []string{
		"mail bob@example.com, card 4111 1111 1111 1111",
		"qty 2 4111 1111 1111 1111 9",
		"Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoiPz8_In0.sig-_x token=abc",
		"sk_live_abc123 password: x " + Hash("x"),
	} {
		f.Add(s)
	}

	e := fuzzEngine(f)
	f.Fuzz(func(t *testing.T, s string) {
		once := e.RedactText(s, nil)
		if twice := e.RedactText(once, nil); twice != once {
			t.Fatalf("not idempotent\n   in %q\n once %q\ntwice %q", s, once, twice)
		}
	})
}
