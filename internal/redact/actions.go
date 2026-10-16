// Package redact holds the redaction engine: the actions applied to
// sensitive values and the logic that finds those values in a transaction.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode/utf8"

	"f5-redactor/internal/config"
)

// hashPrefix marks a hashed value. The prefix makes the output
// self-describing, and lets the tool recognise its own output on a second run
// instead of hashing the hash (which would break idempotency).
const hashPrefix = "sha256:"

var hashedValue = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Actions applies the four redaction actions with the configured settings.
// All methods are pure: same input, same output, no side effects.
type Actions struct {
	maskReplacement string
	keepLast        int
	fill            string
}

// NewActions builds Actions from validated settings.
func NewActions(s config.Settings) Actions {
	return Actions{
		maskReplacement: s.MaskReplacement,
		keepLast:        s.PartialKeepLast,
		fill:            s.PartialFill,
	}
}

// Apply runs the given action on v and returns the redacted value.
//
// An empty string stays empty: there is nothing in it to hide, and keeping it
// as is preserves the shape of the log. "remove" returns "" here; for key
// rules the engine drops the whole key instead of calling Apply.
func (a Actions) Apply(action config.Action, v string) string {
	if v == "" {
		return ""
	}
	switch action {
	case config.ActionMask:
		return a.Mask(v)
	case config.ActionPartial:
		return a.Partial(v)
	case config.ActionHash:
		return Hash(v)
	case config.ActionRemove:
		return ""
	default:
		// Unreachable with a validated config. If it ever happens, fail
		// closed: hide the value rather than pass it through.
		return a.Mask(v)
	}
}

// Mask replaces the whole value with the mask replacement.
func (a Actions) Mask(string) string {
	return a.maskReplacement
}

// Partial keeps the last keepLast characters and replaces every other
// character with the fill character, so the length is preserved:
// "4111111111111111" becomes "************1111".
//
// A value no longer than keepLast is masked completely, because "keeping the
// last 4" of a 4-character value would reveal all of it.
//
// Characters are counted as runes (Unicode code points), not bytes, so
// Hebrew, Japanese or emoji are never cut in the middle.
func (a Actions) Partial(v string) string {
	n := utf8.RuneCountInString(v)
	if n <= a.keepLast {
		return strings.Repeat(a.fill, n)
	}
	runes := []rune(v)
	return strings.Repeat(a.fill, n-a.keepLast) + string(runes[n-a.keepLast:])
}

// Hash replaces the value with "sha256:" followed by the hex SHA-256 digest.
// A value that is already in that form is returned unchanged.
func Hash(v string) string {
	if IsHashed(v) {
		return v
	}
	sum := sha256.Sum256([]byte(v))
	return hashPrefix + hex.EncodeToString(sum[:])
}

// IsHashed reports whether v is exactly a value produced by Hash.
func IsHashed(v string) bool {
	return hashedValue.MatchString(v)
}
