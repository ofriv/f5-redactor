package redact

import "testing"

func TestLuhn(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// Card numbers that appear in input.ndjson.
		{"visa", "4111111111111111", true},
		{"visa 2", "4012888888881881", true},
		{"mastercard", "5555555555554444", true},
		{"amex", "378282246310005", true},
		{"diners", "30569309025904", true},
		{"discover", "6011111111111117", true},
		{"visa with spaces", "4111 1111 1111 1111", true},
		{"mastercard with dashes", "5555-5555-5555-4444", true},
		{"amex grouped 4-6-5", "3782 822463 10005", true},

		// Long numbers from the input that are not cards.
		{"order ref (line 4)", "4111111111111112", false},
		{"request id (line 35)", "1705312800123456", false},
		{"last digit changed", "5555555555554443", false},

		// Classic textbook example.
		{"79927398713", "79927398713", true},
		{"79927398710", "79927398710", false},

		// Not numbers at all.
		{"empty", "", false},
		{"only separators", " - - ", false},
		{"letter inside", "4111x11111111111", false},
		{"dot separator", "4111.1111.1111.1111", false},
		{"plus sign", "+4111111111111111", false},
		{"non-ASCII digit", "٤١١١١١١١١١١١١١١١", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Luhn(tt.in); got != tt.want {
				t.Errorf("Luhn(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
