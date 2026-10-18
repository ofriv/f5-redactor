// Package stream runs the redaction engine over an NDJSON stream, one line
// at a time. It is shared by the CLI and the HTTP service.
//
// Memory use is bounded by the longest accepted line (MaxLineBytes), not by
// the size of the input: one line is read, redacted, written and dropped
// before the next one is read. Time is linear in the input size times the
// number of rules.
package stream

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"f5-redactor/internal/redact"
)

// DefaultMaxLineBytes is the default limit on one input line: large enough
// for any reasonable API transaction, small enough that a few concurrent
// streams cannot exhaust a pod's memory.
const DefaultMaxLineBytes = 10 << 20 // 10 MiB

// ErrLineTooLong is the rejection reason for a line over MaxLineBytes.
var ErrLineTooLong = errors.New("line_too_long")

// Options configures Process.
type Options struct {
	// MaxLineBytes limits one line, without its line ending. A longer line
	// is rejected, and its content is discarded as it is read.
	MaxLineBytes int
	// Warnings, if set, receives one short message per rejected or unusual
	// line, e.g. "line 20: invalid_json". Messages never contain input data.
	Warnings io.Writer
	// MaxWarnings caps the number of warning messages, so a broken input
	// cannot flood the log. The summary still counts every line.
	MaxWarnings int
	// AfterLine, if set, is called after each output line is written. The
	// HTTP service uses it to flush the response while streaming.
	AfterLine func() error
}

// Process reads NDJSON from r, redacts every line with eng and writes the
// result to w.
//
// For each input line:
//   - a valid line is written redacted;
//   - an empty (or whitespace-only) line is skipped and counted;
//   - a line that cannot be parsed, or is too long, is replaced by an error
//     record that contains no input data, only the reason and line number:
//     {"_redactor":{"error":"invalid_json","line":20}}
//
// The error record keeps the output valid NDJSON and tells the consumer that
// a record was dropped and where. Writing the original line (even partly
// redacted) is never safe: if it could not be parsed, we cannot know which
// part of it is sensitive.
//
// Process returns an error only when reading or writing fails.
func Process(r io.Reader, w io.Writer, eng *redact.Engine, opts Options) (*Stats, error) {
	if opts.MaxLineBytes <= 0 {
		opts.MaxLineBytes = DefaultMaxLineBytes
	}
	stats := NewStats()
	lr := newLineReader(r, opts.MaxLineBytes)
	warnings := 0
	warn := func(lineNo int, msg string) {
		if opts.Warnings == nil {
			return
		}
		switch {
		case opts.MaxWarnings > 0 && warnings == opts.MaxWarnings:
			fmt.Fprintf(opts.Warnings, "redactor: more than %d warnings, not showing the rest (see summary)\n", opts.MaxWarnings)
		case opts.MaxWarnings <= 0 || warnings < opts.MaxWarnings:
			fmt.Fprintf(opts.Warnings, "redactor: line %d: %s\n", lineNo, msg)
		}
		warnings++
	}

	var out []byte
	for lineNo := 1; ; lineNo++ {
		line, tooLong, err := lr.next()
		if errors.Is(err, io.EOF) {
			return stats, nil
		}
		if err != nil {
			return stats, fmt.Errorf("read input: %w", err)
		}
		stats.LinesRead++

		out = out[:0]
		switch {
		case tooLong:
			stats.reject(ErrLineTooLong)
			warn(lineNo, ErrLineTooLong.Error())
			out = errorRecord(out, ErrLineTooLong, lineNo)
		default:
			redacted, notice, err := eng.RedactLine(line, stats.Redactions)
			switch {
			case errors.Is(err, redact.ErrEmpty):
				stats.Empty++
				continue
			case err != nil:
				stats.reject(err)
				warn(lineNo, err.Error())
				out = errorRecord(out, err, lineNo)
			default:
				if notice != "" {
					stats.Notices[notice]++
					warn(lineNo, notice+" (redacted)")
				}
				out = append(out, redacted...)
			}
		}

		out = append(out, '\n')
		if _, err := w.Write(out); err != nil {
			return stats, fmt.Errorf("write output: %w", err)
		}
		stats.LinesWritten++
		if opts.AfterLine != nil {
			if err := opts.AfterLine(); err != nil {
				return stats, fmt.Errorf("write output: %w", err)
			}
		}
	}
}

// errorRecord appends the replacement written for a line that could not be
// processed. The reason is one of the engine's fixed error values.
func errorRecord(buf []byte, reason error, lineNo int) []byte {
	return fmt.Appendf(buf, `{"_redactor":{"error":%q,"line":%d}}`, reason.Error(), lineNo)
}

// lineReader reads lines of at most max bytes, using memory bounded by max
// no matter how long a line in the input is.
type lineReader struct {
	br    *bufio.Reader
	max   int
	buf   []byte
	first bool
}

func newLineReader(r io.Reader, max int) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, 64<<10), max: max, first: true}
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// next returns the next line without its line ending ("\n" or "\r\n"). The
// returned slice is only valid until the next call. If the line was longer
// than max, tooLong is true and the line's content has been discarded. The
// last line of the input does not need a trailing newline. At the end of
// the input next returns io.EOF.
func (lr *lineReader) next() (line []byte, tooLong bool, err error) {
	lr.buf = lr.buf[:0]
	sawData := false
	for {
		// ReadSlice returns at most one buffer (64 KiB) at a time, so a huge
		// line is consumed in pieces and the pieces past the limit are
		// dropped instead of stored.
		chunk, err := lr.br.ReadSlice('\n')
		sawData = sawData || len(chunk) > 0
		if !tooLong {
			// +2 leaves room for the "\r\n" that is trimmed below.
			if len(lr.buf)+len(chunk) > lr.max+2 {
				tooLong = true
				lr.buf = lr.buf[:0]
			} else {
				lr.buf = append(lr.buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if !sawData {
				return nil, false, io.EOF
			}
			break // last line, no trailing newline
		}
		if err != nil {
			return nil, false, err
		}
		break
	}

	line = bytes.TrimSuffix(lr.buf, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if lr.first {
		lr.first = false
		line = bytes.TrimPrefix(line, utf8BOM)
	}
	if tooLong || len(line) > lr.max {
		return nil, true, nil
	}
	return line, false, nil
}
