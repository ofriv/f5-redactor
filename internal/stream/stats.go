package stream

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"

	"f5-redactor/internal/redact"
)

// Stats counts what happened to a stream. It holds counts and fixed reason
// names only, never input data, so it is always safe to log.
type Stats struct {
	LinesRead    int            `json:"lines_read"`
	LinesWritten int            `json:"lines_written"`
	Empty        int            `json:"empty_lines"`
	Rejected     map[string]int `json:"rejected"`   // reason -> lines
	Notices      map[string]int `json:"notices"`    // notice -> lines
	Redactions   redact.Counts  `json:"redactions"` // rule name -> redactions
}

// NewStats returns empty Stats.
func NewStats() *Stats {
	return &Stats{Rejected: map[string]int{}, Notices: map[string]int{}, Redactions: redact.Counts{}}
}

func (s *Stats) reject(reason error) {
	s.Rejected[reason.Error()]++
}

// RejectedTotal is the number of lines replaced by an error record.
func (s *Stats) RejectedTotal() int {
	total := 0
	for _, n := range s.Rejected {
		total += n
	}
	return total
}

// WriteText writes a short human-readable summary. rules lists every rule
// name in config order, so rules that matched nothing are shown with 0.
func (s *Stats) WriteText(w io.Writer, rules []string) error {
	p := &printer{w: w}
	p.printf("redactor: %d lines read, %d written, %d rejected, %d empty\n",
		s.LinesRead, s.LinesWritten, s.RejectedTotal(), s.Empty)

	p.printf("redactions by rule:\n")
	for _, name := range rules {
		p.printf("  %-22s %d\n", name, s.Redactions[name])
	}
	if len(s.Rejected) > 0 {
		p.printf("rejected lines by reason:\n")
		for _, reason := range slices.Sorted(maps.Keys(s.Rejected)) {
			p.printf("  %-22s %d\n", reason, s.Rejected[reason])
		}
	}
	if len(s.Notices) > 0 {
		p.printf("notices:\n")
		for _, notice := range slices.Sorted(maps.Keys(s.Notices)) {
			p.printf("  %-22s %d\n", notice, s.Notices[notice])
		}
	}
	return p.err
}

// WriteJSON writes the summary as one JSON line, for machines. Rules that
// matched nothing are included with 0.
func (s *Stats) WriteJSON(w io.Writer, rules []string) error {
	out := *s
	out.Redactions = redact.Counts{}
	for _, name := range rules {
		out.Redactions[name] = 0
	}
	maps.Copy(out.Redactions, s.Redactions)
	return json.NewEncoder(w).Encode(out)
}

// printer remembers the first write error so the caller checks it once.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}
