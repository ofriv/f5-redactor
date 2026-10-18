// Package redact holds the redaction engine: the actions applied to
// sensitive values and the logic that finds those values in a transaction.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"f5-redactor/internal/config"
)

// The prefixes mark a hashed value. They make the output self-describing
// (which method was used), and let the tool recognise its own output on a
// second run instead of hashing the hash (which would break idempotency).
const (
	hashPrefix = "sha256:"      // plain SHA-256, as the assignment asks
	hmacPrefix = "hmac-sha256:" // HMAC-SHA256 with a secret key
)

var hashedValue = regexp.MustCompile(`^(?:sha256|hmac-sha256):[0-9a-f]{64}$`)

// MinHashKeyBytes is the shortest accepted HMAC key. A short key can be
// guessed, and then the keyed hash protects no better than a plain one.
const MinHashKeyBytes = 32

// ValidateHashKey checks an HMAC key. The error never contains the key.
func ValidateHashKey(key []byte) error {
	if len(key) < MinHashKeyBytes {
		return fmt.Errorf("hash key is %d bytes, need at least %d (for example: openssl rand -hex 32)", len(key), MinHashKeyBytes)
	}
	return nil
}

// Actions applies the four redaction actions with the configured settings.
// All methods are pure: same input, same output, no side effects.
type Actions struct {
	maskReplacement string
	keepLast        int
	fill            string
	hashKey         []byte // empty: plain SHA-256; set: HMAC-SHA256
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
		return a.Hash(v)
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

// Hash hashes v with the configured method: HMAC-SHA256 when a key is set,
// plain SHA-256 otherwise.
//
// Why a key: a plain SHA-256 of an email (or of any value with few possible
// inputs, like a 4-digit PIN) can be reversed by hashing candidates and
// comparing. Without the key nobody can compute the HMAC, yet the same
// value still gives the same output, so values can still be compared and
// counted across logs.
func (a Actions) Hash(v string) string {
	if len(a.hashKey) == 0 {
		return Hash(v)
	}
	if IsHashed(v) {
		return v
	}
	mac := hmac.New(sha256.New, a.hashKey)
	mac.Write([]byte(v))
	return hmacPrefix + hex.EncodeToString(mac.Sum(nil))
}

// Hash replaces the value with "sha256:" followed by the hex SHA-256 digest.
// A value that is already hashed (by either method) is returned unchanged.
func Hash(v string) string {
	if IsHashed(v) {
		return v
	}
	sum := sha256.Sum256([]byte(v))
	return hashPrefix + hex.EncodeToString(sum[:])
}

// IsHashed reports whether v is exactly a value produced by Hash or by
// Actions.Hash.
func IsHashed(v string) bool {
	return hashedValue.MatchString(v)
}
