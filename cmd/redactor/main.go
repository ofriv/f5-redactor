// Command redactor redacts sensitive data from NDJSON API traffic logs.
//
//	redactor [--rules rules.yaml] [input-file]   # reads stdin if no file is given
//	redactor --serve --addr :8080 --rules /etc/redactor/rules.yaml
//
// The redacted NDJSON goes to stdout; warnings and the summary go to stderr.
// With --serve it runs the HTTP service instead (see internal/server).
//
// Exit codes:
//
//	0  the input was processed (rejected lines are reported, not fatal)
//	1  reading the input or writing the output failed
//	2  bad usage, or the rules file could not be loaded
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"f5-redactor/internal/config"
	"f5-redactor/internal/redact"
	"f5-redactor/internal/server"
	"f5-redactor/internal/stream"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is main without the process globals, so tests can call it directly.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("redactor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rulesPath := fs.String("rules", "rules.yaml", "path to the rules file")
	maxLine := fs.Int("max-line-bytes", stream.DefaultMaxLineBytes, "longest accepted input line, in bytes")
	summaryFormat := fs.String("summary-format", "text", "summary format on stderr: text or json")
	checkConfig := fs.Bool("check-config", false, "validate the rules file and exit")
	serve := fs.Bool("serve", false, "run the HTTP service instead of processing a file")
	addr := fs.String("addr", ":8080", "listen address for --serve")
	maxConcurrent := fs.Int("max-concurrent", server.DefaultMaxConcurrent, "most /redact requests served at once (--serve)")
	shutdownDelay := fs.Duration("shutdown-delay", 5*time.Second, "time between failing /readyz and closing the listener at shutdown (--serve)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: redactor [flags] [input-file]")
		fmt.Fprintln(stderr, "       redactor --serve [--addr :8080] [flags]")
		fmt.Fprintln(stderr, "Reads NDJSON from input-file (or stdin) and writes it redacted to stdout.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "redactor: at most one input file")
		fs.Usage()
		return exitUsage
	}
	if *summaryFormat != "text" && *summaryFormat != "json" {
		fmt.Fprintf(stderr, "redactor: --summary-format must be text or json, got %q\n", *summaryFormat)
		return exitUsage
	}
	if *maxLine <= 0 {
		fmt.Fprintln(stderr, "redactor: --max-line-bytes must be positive")
		return exitUsage
	}
	if *serve && fs.NArg() > 0 {
		fmt.Fprintln(stderr, "redactor: --serve does not take an input file")
		return exitUsage
	}
	if *maxConcurrent <= 0 {
		fmt.Fprintln(stderr, "redactor: --max-concurrent must be positive")
		return exitUsage
	}

	// Load the rules before touching the input: with broken rules nothing
	// is processed, so nothing can pass through unredacted.
	cfg, err := config.Load(*rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "redactor: %v\n", err)
		return exitUsage
	}
	if *checkConfig {
		fmt.Fprintf(stdout, "%s: OK (%d key rules, %d value rules)\n", *rulesPath, len(cfg.KeyRules), len(cfg.ValueRules))
		return exitOK
	}
	eng := redact.New(cfg)

	if *serve {
		logger := slog.New(slog.NewJSONHandler(stderr, nil))
		ln, err := net.Listen("tcp", *addr)
		if err != nil {
			logger.Error("listen failed", "addr", *addr, "error", err.Error())
			return exitFailure
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		srv := server.New(eng, server.Options{MaxLineBytes: *maxLine, MaxConcurrent: *maxConcurrent, Logger: logger})
		if err := runServer(ctx, ln, srv, logger, *shutdownDelay); err != nil {
			logger.Error("server failed", "error", err.Error())
			return exitFailure
		}
		return exitOK
	}

	in := stdin
	if path := fs.Arg(0); path != "" && path != "-" {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(stderr, "redactor: %v\n", err)
			return exitFailure
		}
		defer f.Close()
		in = f
	}

	out := bufio.NewWriterSize(stdout, 64<<10)
	stats, err := stream.Process(in, out, eng, stream.Options{
		MaxLineBytes: *maxLine,
		Warnings:     stderr,
		MaxWarnings:  20,
		// Flush whenever the input has no full line waiting, so piping a
		// live log (tail -f access.log | redactor) shows each line at once.
		Flush: out.Flush,
	})
	if flushErr := out.Flush(); err == nil && flushErr != nil {
		err = fmt.Errorf("write output: %w", flushErr)
	}

	if *summaryFormat == "json" {
		_ = stats.WriteJSON(stderr, eng.RuleNames())
	} else {
		_ = stats.WriteText(stderr, eng.RuleNames())
	}
	if err != nil {
		fmt.Fprintf(stderr, "redactor: %v\n", err)
		return exitFailure
	}
	return exitOK
}
