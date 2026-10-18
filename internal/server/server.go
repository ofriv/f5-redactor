// Package server is the HTTP service mode of the redactor.
//
//	POST /redact   NDJSON in, redacted NDJSON out, streamed line by line
//	GET  /healthz  liveness: 200 while the process can answer at all
//	GET  /readyz   readiness: 200 when rules are loaded and the server is
//	               not shutting down, 503 otherwise
//
// The server is only built from an already loaded rule set, so it cannot
// run without rules: if rules.yaml cannot be loaded, the process exits
// before it listens, and no traffic is ever passed through unredacted.
package server

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"f5-redactor/internal/redact"
	"f5-redactor/internal/stream"
)

// DefaultMaxConcurrent limits how many /redact requests run at once. Each
// one can hold up to MaxLineBytes (10 MiB by default) in memory, so the
// limit keeps the worst case bounded: 64 x 10 MiB.
const DefaultMaxConcurrent = 64

// DefaultIdleTimeout is how long a /redact request may go without a full
// line in or out. Without it, a client that sends a byte and stalls (or
// stops reading the response) holds a request slot forever, and a few such
// clients take the whole service down.
const DefaultIdleTimeout = time.Minute

// summaryTrailer is the HTTP trailer that carries a request's summary. The
// response body has already been sent by then, so a trailer is the only
// place to report the counts back to the client.
const summaryTrailer = "X-Redactor-Summary"

// Options configures the server.
type Options struct {
	MaxLineBytes  int
	MaxConcurrent int
	IdleTimeout   time.Duration
	Logger        *slog.Logger
}

// Server serves the redaction API.
type Server struct {
	engine  *redact.Engine
	opts    Options
	slots   chan struct{} // one token per running /redact request
	ready   atomic.Bool
	logger  *slog.Logger
	handler http.Handler
}

// New returns a server that redacts with eng. It starts ready.
func New(eng *redact.Engine, opts Options) *Server {
	if opts.MaxLineBytes <= 0 {
		opts.MaxLineBytes = stream.DefaultMaxLineBytes
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = DefaultMaxConcurrent
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		engine: eng,
		opts:   opts,
		slots:  make(chan struct{}, opts.MaxConcurrent),
		logger: opts.Logger,
	}
	s.ready.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /redact", s.handleRedact)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	s.handler = mux
	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// SetReady changes what /readyz reports. It is set to false at shutdown,
// so the load balancer stops sending new requests while running ones
// finish.
func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !s.ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("shutting down\n"))
		return
	}
	_, _ = w.Write([]byte("ready\n"))
}

func (s *Server) handleRedact(w http.ResponseWriter, r *http.Request) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many concurrent requests", http.StatusServiceUnavailable)
		s.logger.Warn("redact request rejected", "reason", "too_many_requests")
		return
	}

	start := time.Now()
	rc := http.NewResponseController(w)
	// HTTP/1.1 servers normally stop reading the request once the response
	// starts. Full duplex lets us read and write at the same time, which is
	// what streaming needs. HTTP/2 is always full duplex, and returns an
	// error here that is safe to ignore.
	_ = rc.EnableFullDuplex()

	// Every finished line moves the read and write deadlines forward, so a
	// long, steady stream runs as long as it needs, but a stalled client is
	// cut off after IdleTimeout and frees its slot.
	extend := func() {
		deadline := time.Now().Add(s.opts.IdleTimeout)
		_ = rc.SetReadDeadline(deadline)
		_ = rc.SetWriteDeadline(deadline)
	}
	extend()
	defer func() { // no stale deadline for the next request on this connection
		_ = rc.SetReadDeadline(time.Time{})
		_ = rc.SetWriteDeadline(time.Time{})
	}()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Trailer", summaryTrailer)
	w.WriteHeader(http.StatusOK)

	out := bufio.NewWriterSize(w, 32<<10)
	flush := func() error {
		if err := out.Flush(); err != nil {
			return err
		}
		return rc.Flush()
	}
	stats, err := stream.Process(r.Body, out, s.engine, stream.Options{
		MaxLineBytes: s.opts.MaxLineBytes,
		Flush:        flush,
		AfterLine:    func() error { extend(); return nil },
	})
	if err == nil {
		err = flush()
	}

	summary := struct {
		*stream.Stats
		Error string `json:"error,omitempty"`
	}{Stats: stats}
	if err != nil {
		// The status line is gone already; the trailer and the log are the
		// only places left to report the failure. The error is not
		// included: an I/O error never needs input data to be understood.
		summary.Error = "stream_failed"
	}
	if b, jerr := json.Marshal(summary); jerr == nil {
		w.Header().Set(summaryTrailer, string(b))
	}

	attrs := []any{
		"lines_read", stats.LinesRead,
		"lines_written", stats.LinesWritten,
		"rejected", stats.RejectedTotal(),
		"redactions", map[string]int(stats.Redactions),
		"duration_ms", time.Since(start).Milliseconds(),
	}
	if err != nil {
		s.logger.Warn("redact request failed", append(attrs, "error", summary.Error)...)
		return
	}
	s.logger.Info("redact request", attrs...)
}
