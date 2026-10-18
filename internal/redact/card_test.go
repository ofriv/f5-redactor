package redact

import (
	"strings"
	"testing"
)

// Regression tests for card numbers written with spaces or dashes. The
// provided pattern \b\d{13,19}\b only matches unbroken digits, so the cards
// in input lines 1, 6, 36 and 44 were left in the output.
func TestCardNumbersWithSeparators(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"spaces (line 1)", "card 4111 1111 1111 1111 on file", "card ***************1111 on file"},
		{"dashes (line 6)", "please charge 5555-5555-5555-4444 and send the receipt", "please charge ***************4444 and send the receipt"},
		{"amex 4-6-5 grouping (line 36)", "amex 3782 822463 10005", "amex *************0005"},
		{"array item (line 44)", "5555 5555 5555 4444", "***************4444"},
		{"no separators still works", "first 4111111111111111 then", "first ************1111 then"},
		{"mixed separators", "4111-1111 1111-1111", "***************1111"},

		{"two cards in a row", "4111111111111111 5555555555554444", "************1111 ************4444"},

		// Must not be redacted.
		{"fails Luhn with spaces", "ref 4111 1111 1111 1112", "ref 4111 1111 1111 1112"},
		{"too short: 12 digits", "1234 5678 9012", "1234 5678 9012"},
		{"phone number (line 37)", "+1 (415) 555-0132", "+1 (415) 555-0132"},
		{"ssn (line 37)", "123-45-6789", "123-45-6789"},
		{"date and time", "2025-01-15 10:00:20", "2025-01-15 10:00:20"},
		{"double space breaks the number", "4111  1111  1111  1111", "4111  1111  1111  1111"},
		{"digits inside a word", "id4111111111111111x", "id4111111111111111x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.RedactText(tt.in, nil); got != tt.want {
				t.Errorf("RedactText(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

// The pattern matches the longest run of digit groups. When that run fails
// Luhn as a whole, a valid card inside it must still be found. A random
// stretch of digits next to the card can pass Luhn by chance and overlap it;
// the merged region is then masked together, so a few harmless digits may be
// masked too. What must hold: no more than the card's last 4 digits remain,
// and the words around the run are untouched.
func TestCardInsideLongerDigitRun(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct {
		in, keepPrefix, keepSuffix string
	}{
		{"qty 2 4111 1111 1111 1111", "qty ", ""},
		{"4111 1111 1111 1111 2 left", "", " left"},
		{"1234 4111 1111 1111 1111", "", ""},
		{"1 2 3 4 5 6 7 4111 1111 1111 1111", "1 2 ", ""},
		{"ref 9 9 5555-5555-5555-4444 ok", "ref ", " ok"},
	}
	for _, tt := range tests {
		got := e.RedactText(tt.in, nil)
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, got)
		// The card's first 12 digits are never all visible; at most 4 of
		// the card remain, plus a few digits of the run outside it.
		if strings.Contains(digits, "411111111111") || strings.Contains(digits, "555555555555") ||
			strings.Contains(got, "4111 1111") || strings.Contains(got, "5555-5555") {
			t.Errorf("card not covered: %q -> %q", tt.in, got)
		}
		if !strings.HasPrefix(got, tt.keepPrefix) || !strings.HasSuffix(got, tt.keepSuffix) {
			t.Errorf("text around the run changed: %q -> %q", tt.in, got)
		}
	}
}
