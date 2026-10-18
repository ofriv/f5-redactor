package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"f5-redactor/internal/config"
	"f5-redactor/internal/redact"
	"f5-redactor/internal/server"
)

// With rules that cannot be loaded, --serve exits before it ever listens.
func TestServeRefusesToStartWithBadRules(t *testing.T) {
	code, _, stderr := runCLI(t, "", "--serve", "--addr", "127.0.0.1:0", "--rules", "missing.yaml")
	if code != exitUsage || !strings.Contains(stderr, "missing.yaml") {
		t.Errorf("code %d, stderr %q", code, stderr)
	}
}

func TestServeFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--serve", "--rules", rulesFile, "input.ndjson"},
		{"--serve", "--rules", rulesFile, "--max-concurrent", "0"},
	} {
		if code, _, _ := runCLI(t, "", args...); code != exitUsage {
			t.Errorf("args %v: code %d, want %d", args, code, exitUsage)
		}
	}
}

// Start the real server, use it, then shut it down as on SIGTERM.
func TestRunServerShutsDownGracefully(t *testing.T) {
	cfg, err := config.Load(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	srv := server.New(redact.New(cfg), server.Options{Logger: logger})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runServer(ctx, ln, srv, logger, 300*time.Millisecond) }()

	base := "http://" + ln.Addr().String()
	resp, err := http.Post(base+"/redact", "application/x-ndjson", strings.NewReader(`{"body":{"password":"x"}}`+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"body":{"password":"****"}}`+"\n" {
		t.Errorf("body = %q", body)
	}

	cancel() // SIGTERM
	time.Sleep(100 * time.Millisecond)
	if resp, err := http.Get(base + "/readyz"); err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("during the shutdown delay /readyz should be 503 (err %v)", err)
	} else {
		resp.Body.Close()
	}

	select {
	case err := <-result:
		if err != nil {
			t.Errorf("runServer: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop")
	}
	if !strings.Contains(logs.String(), `"msg":"stopped"`) {
		t.Errorf("missing stop log: %s", logs.String())
	}
}
