package redact

import "testing"

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
