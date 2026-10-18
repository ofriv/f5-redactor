// Command redactor redacts sensitive data from NDJSON API traffic logs.
//
//	redactor [--rules rules.yaml] [input-file]   # reads stdin if no file is given
//
// The redacted NDJSON goes to stdout; warnings and the summary go to stderr.
//
// Exit codes:
//
//	0  the input was processed (rejected lines are reported, not fatal)
//	1  reading the input or writing the output failed
//	2  bad usage, or the rules file could not be loaded
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"f5-redactor/internal/config"
	"f5-redactor/internal/redact"
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
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: redactor [flags] [input-file]")
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

	eng := redact.New(cfg)
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
