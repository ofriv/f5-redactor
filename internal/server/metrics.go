package server

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"f5-redactor/internal/stream"
)

// metrics holds the counters served at GET /metrics, written in the
// Prometheus text format by hand: a few counters do not justify a
// dependency. Counts come from each request's summary when it ends, so a
// long stream shows up when it finishes. They never hold input data, only
// rule names and fixed reasons.
type metrics struct {
	mu            sync.Mutex
	requests      map[string]int64 // result: ok, stream_failed, busy
	durationSum   float64          // seconds, finished requests
	durationCount int64
	linesRead     int64
	rejected      map[string]int64 // reason -> lines
	redactions    map[string]int64 // rule -> redactions
	reloads       map[string]int64 // result: ok, failed
}

func newMetrics() *metrics {
	return &metrics{
		requests:   map[string]int64{},
		rejected:   map[string]int64{},
		redactions: map[string]int64{},
		reloads:    map[string]int64{},
	}
}

func (m *metrics) busy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests["busy"]++
}

func (m *metrics) finished(stats *stream.Stats, failed bool, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if failed {
		m.requests["stream_failed"]++
	} else {
		m.requests["ok"]++
	}
	m.durationSum += d.Seconds()
	m.durationCount++
	m.linesRead += int64(stats.LinesRead)
	for reason, n := range stats.Rejected {
		m.rejected[reason] += int64(n)
	}
	for rule, n := range stats.Redactions {
		m.redactions[rule] += int64(n)
	}
}

func (m *metrics) reloaded(ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.reloads["ok"]++
	} else {
		m.reloads["failed"]++
	}
}

// write writes every metric. rules lists the current rule names, so a rule
// that has matched nothing yet is shown with 0.
func (m *metrics) write(w io.Writer, rules []string, inFlight int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	family := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	labelled := func(name, label string, values map[string]int64, always ...string) {
		all := maps.Clone(values)
		for _, v := range always {
			all[v] += 0
		}
		for _, v := range slices.Sorted(maps.Keys(all)) {
			fmt.Fprintf(&b, "%s{%s=\"%s\"} %d\n", name, label, escapeLabel(v), all[v])
		}
	}

	family("redactor_requests_total", "counter", "/redact requests by result.")
	labelled("redactor_requests_total", "result", m.requests, "ok", "stream_failed", "busy")
	family("redactor_requests_in_flight", "gauge", "/redact requests running now.")
	fmt.Fprintf(&b, "redactor_requests_in_flight %d\n", inFlight)
	family("redactor_request_duration_seconds", "summary", "Duration of finished /redact requests.")
	fmt.Fprintf(&b, "redactor_request_duration_seconds_sum %g\nredactor_request_duration_seconds_count %d\n", m.durationSum, m.durationCount)
	family("redactor_lines_read_total", "counter", "Input lines read.")
	fmt.Fprintf(&b, "redactor_lines_read_total %d\n", m.linesRead)
	family("redactor_lines_rejected_total", "counter", "Lines replaced by an error record, by reason.")
	labelled("redactor_lines_rejected_total", "reason", m.rejected)
	family("redactor_redactions_total", "counter", "Redactions by rule.")
	labelled("redactor_redactions_total", "rule", m.redactions, rules...)
	family("redactor_rules_reloads_total", "counter", "Rule reloads (SIGHUP) by result.")
	labelled("redactor_rules_reloads_total", "result", m.reloads, "ok", "failed")

	_, err := io.WriteString(w, b.String())
	return err
}

// escapeLabel escapes a label value as the text format requires.
func escapeLabel(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}
