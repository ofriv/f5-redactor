// Package stream runs the redaction engine over an NDJSON stream, one line
// at a time. It is shared by the CLI and the HTTP service.
//
// Memory use is bounded by the longest accepted line (MaxLineBytes) plus one
// batch of lines (batchBytes), not by the size of the input. Time is linear
// in the input size times the number of rules.
package stream

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"f5-redactor/internal/redact"
)

// DefaultMaxLineBytes is the default limit on one input line: large enough
// for any reasonable API transaction, small enough that a few concurrent
// streams cannot exhaust a pod's memory.
const DefaultMaxLineBytes = 10 << 20 // 10 MiB

// batchBytes caps the input held in one batch of lines that are redacted in
// parallel (a single longer line makes a batch of its own). A batch also
// ends when no complete line is waiting in the input, so a client sending
// one line at a time gets each line back at once.
const batchBytes = 1 << 20 // 1 MiB

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
	// Workers is how many lines are redacted in parallel (at least 1). The
	// output keeps the input order.
	Workers int
	// AfterLine, if set, is called after each output line is written.
	AfterLine func() error
	// Flush, if set, is called after writing a line when no complete input
	// line is waiting, i.e. just before a read that may block. A writer that
	// buffers its output can then push what it has to the reader: a client
	// streaming lines one by one gets each redacted line back right away,
	// while a large upload is still written in big blocks. The caller must
	// still flush once more after Process returns.
	Flush func() error
}

// Process reads NDJSON from r, redacts every line with eng and writes the
// result to w.
//
// For each input line:
//   - a valid line is written redacted;
//   - an empty (or whitespace-only) line is written back as it is, so the
//     output has exactly one line per input line;
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

	var (
		batch      []job
		lineNo     int
		pending    job // a line read but left for the next batch
		hasPending bool
	)
	for {
		// Take the lines that are already waiting, up to batchBytes in all
		// (or one longer line). Only the first read may block.
		batch = batch[:0]
		size := 0
		for {
			var j job
			if hasPending {
				j, hasPending = pending, false
			} else {
				line, tooLong, err := lr.next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return stats, fmt.Errorf("read input: %w", err)
				}
				lineNo++
				stats.LinesRead++
				// next reuses its buffer, so the batch keeps its own copy.
				j = job{lineNo: lineNo, line: bytes.Clone(line), tooLong: tooLong}
			}
			if len(batch) > 0 && size+len(j.line) > batchBytes {
				pending, hasPending = j, true
				break
			}
			batch = append(batch, j)
			size += len(j.line)
			if !lr.hasBufferedLine() {
				break
			}
		}
		if len(batch) == 0 {
			return stats, nil
		}

		redactBatch(eng, batch, opts.Workers, stats.Redactions)

		// Write in input order.
		for i := range batch {
			j := &batch[i]
			switch {
			case j.tooLong:
				stats.reject(ErrLineTooLong)
				warn(j.lineNo, ErrLineTooLong.Error())
			case errors.Is(j.err, redact.ErrEmpty):
				// Nothing to hide: written back as it came, so output line N
				// is always input line N.
				stats.Empty++
			case j.err != nil:
				stats.reject(j.err)
				warn(j.lineNo, j.err.Error())
			case j.notice != "":
				stats.Notices[j.notice]++
				warn(j.lineNo, j.notice+" (redacted)")
			}
			if _, err := w.Write(j.out); err != nil {
				return stats, fmt.Errorf("write output: %w", err)
			}
			stats.LinesWritten++
			if opts.AfterLine != nil {
				if err := opts.AfterLine(); err != nil {
					return stats, fmt.Errorf("write output: %w", err)
				}
			}
		}
		if opts.Flush != nil && !hasPending && !lr.hasBufferedLine() {
			if err := opts.Flush(); err != nil {
				return stats, fmt.Errorf("write output: %w", err)
			}
		}
	}
}

// job is one input line and, once redacted, its output line.
type job struct {
	lineNo  int
	line    []byte
	tooLong bool

	out    []byte // the line to write, with its "\n"
	err    error  // why the line was rejected, or redact.ErrEmpty
	notice string
}

// redactBatch redacts every line of batch, with up to workers goroutines.
// Each goroutine counts into its own map; the counts are added to counts at
// the end.
func redactBatch(eng *redact.Engine, batch []job, workers int, counts redact.Counts) {
	workers = max(1, min(workers, len(batch)))
	if workers == 1 {
		for i := range batch {
			redactJob(eng, &batch[i], counts)
		}
		return
	}
	var (
		next atomic.Int64
		wg   sync.WaitGroup
		mu   sync.Mutex
	)
	for range workers {
		wg.Go(func() {
			own := redact.Counts{}
			for {
				i := int(next.Add(1)) - 1
				if i >= len(batch) {
					break
				}
				redactJob(eng, &batch[i], own)
			}
			mu.Lock()
			for name, n := range own {
				counts[name] += n
			}
			mu.Unlock()
		})
	}
	wg.Wait()
}

func redactJob(eng *redact.Engine, j *job, counts redact.Counts) {
	if j.tooLong {
		j.out = errorRecord(nil, ErrLineTooLong, j.lineNo)
	} else {
		redacted, notice, err := eng.RedactLine(j.line, counts)
		switch {
		case errors.Is(err, redact.ErrEmpty):
			j.out, j.err = j.line, err
		case err != nil:
			j.out, j.err = errorRecord(nil, err, j.lineNo), err
		default:
			j.out, j.notice = redacted, notice
		}
	}
	j.out = append(j.out, '\n')
	j.line = nil
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

// hasBufferedLine reports whether a whole line has already been read from
// the input, so the next call to next will not block.
func (lr *lineReader) hasBufferedLine() bool {
	buffered, _ := lr.br.Peek(lr.br.Buffered())
	return bytes.IndexByte(buffered, '\n') >= 0
}

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
