package redact

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	"f5-redactor/internal/config"
)

// maxTextPasses bounds the re-scan loop in RedactText. With a validated config
// the loop settles in one or two passes; the cap only protects against a rule
// set whose replacements keep creating new matches.
const maxTextPasses = 8

// hashToken finds values produced by Hash (either method) inside a longer
// text. "hmac-sha256:" contains "sha256:", so one pattern finds both.
var hashToken = regexp.MustCompile(`(?:hmac-)?sha256:[0-9a-f]{64}`)

// RedactText applies every value rule to s and returns the redacted text.
// Redactions are added to counts.
//
// How it works:
//
//  1. Every rule is matched against the original text; matches rejected by
//     the rule's validator (e.g. Luhn) are dropped.
//  2. Matches that overlap are merged into one region, so no part of any
//     match is left in the output. The region gets the action of the rule
//     listed first in rules.yaml. If the merged region came from different
//     rules and that action is "partial", it is upgraded to "mask", because
//     the 4 characters it would keep may belong to the other match.
//  3. All regions are replaced in a single left-to-right pass.
//  4. The result is scanned again until nothing changes. Deleting text (the
//     "remove" action) can join two pieces into a new match, e.g.
//     "bob@exa#mple.com" with "#" removed becomes an email. Stopping only when
//     a pass finds nothing is what makes the output idempotent: running the
//     tool on its own output finds nothing to change.
func (e *Engine) RedactText(s string, counts Counts) string {
	for range maxTextPasses {
		out, changed := e.redactTextOnce(s, counts)
		if !changed {
			return out
		}
		s = out
	}
	return s
}

// match is one rule match: the byte range s[start:end] and the index of the
// rule in e.valueRules (lower index = listed earlier = higher priority).
type match struct {
	start, end int
	rule       int
}

func (e *Engine) redactTextOnce(s string, counts Counts) (string, bool) {
	matches := e.findMatches(s)
	if len(matches) == 0 {
		return s, false
	}

	slices.SortFunc(matches, func(a, b match) int {
		return cmp.Compare(a.start, b.start)
	})

	var b strings.Builder
	b.Grow(len(s))
	last, changed := 0, false

	for i := 0; i < len(matches); {
		// Grow the region while the next match starts inside it.
		region := matches[i]
		first, mixed := region.rule, false
		j := i + 1
		for ; j < len(matches) && matches[j].start < region.end; j++ {
			region.end = max(region.end, matches[j].end)
			region.rule = min(region.rule, matches[j].rule)
			if matches[j].rule != first {
				mixed = true
			}
		}
		i = j

		rule := &e.valueRules[region.rule]
		action := rule.Action
		if mixed && action == config.ActionPartial {
			action = config.ActionMask
		}

		original := s[region.start:region.end]
		replacement := e.actions.Apply(action, original)
		b.WriteString(s[last:region.start])
		b.WriteString(replacement)
		last = region.end

		if replacement != original {
			changed = true
			counts.add(rule.Name)
		}
	}
	b.WriteString(s[last:])
	return b.String(), changed
}

// findMatches returns all validated matches of all value rules in s, except
// matches that touch a hash produced by an earlier run.
func (e *Engine) findMatches(s string) []match {
	var matches []match
	for i := range e.valueRules {
		r := &e.valueRules[i]
		for _, m := range r.Pattern.FindAllStringIndex(s, -1) {
			if m[0] == m[1] {
				continue // empty match: nothing to redact
			}
			if validate(r.Validator, s[m[0]:m[1]]) {
				matches = append(matches, match{start: m[0], end: m[1], rule: i})
				continue
			}
			matches = e.rescueRejected(matches, i, s, m[0], m[1])
		}
	}

	if len(matches) > 0 && strings.Contains(s, hashPrefix) {
		matches = e.dropHashMatches(matches, s)
	}
	return matches
}

// rescueRejected handles a match that its validator rejected.
//
// The regex engine returns the longest match at the leftmost position. For
// cards that is the longest run of digit groups, and a valid card can hide
// inside a run that fails Luhn as a whole: in "qty 2 4111 1111 1111 1111"
// the first match is "2 4111 1111 1111 1111" (17 digits). Dropping it would
// leak the card. So inside the rejected match we try every word start, and
// at each one take the longest match that the validator accepts.
//
// The candidates may overlap each other (in a long run of digits a random
// stretch passes Luhn 1 time in 10). That is fine: overlapping matches are
// merged into one region, so the real card is always covered. The cost is
// that a few harmless digits next to it may be masked too.
func (e *Engine) rescueRejected(matches []match, rule int, s string, start, end int) []match {
	r := &e.valueRules[rule]
	for p := start; p < end; p = nextWordStart(s, p) {
		// Matching on s[p:] treats p as the start of the text. That gives
		// the same \b result as in s only because p is at a word start.
		loc := e.anchoredStart[rule].FindStringIndex(s[p:])
		if loc == nil {
			continue
		}
		for q := p + loc[1]; q > p; q-- {
			// Cut only before a non-word character, so a \b at the end of
			// the pattern gives the same result as in s.
			if q < len(s) && isWordByte(s[q]) {
				continue
			}
			if e.anchoredFull[rule].MatchString(s[p:q]) && validate(r.Validator, s[p:q]) {
				matches = append(matches, match{start: p, end: q, rule: rule})
				break
			}
		}
	}
	return matches
}

// nextWordStart returns the next index after p that starts a word (preceded
// by a non-word byte), or len(s).
func nextWordStart(s string, p int) int {
	for p++; p < len(s); p++ {
		if !isWordByte(s[p-1]) {
			return p
		}
	}
	return len(s)
}

// isWordByte matches the regexp \b definition of a word character (ASCII).
func isWordByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// dropHashMatches removes matches that touch a hash produced by an earlier
// run. Leaving those alone guarantees that a hash is never redacted again,
// whatever the rules are.
func (e *Engine) dropHashMatches(matches []match, s string) []match {
	hashes := hashToken.FindAllStringIndex(s, -1)
	return slices.DeleteFunc(matches, func(m match) bool {
		for _, h := range hashes {
			if m.start < h[1] && h[0] < m.end {
				return true
			}
		}
		return false
	})
}
