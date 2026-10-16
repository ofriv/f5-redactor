package redact

// Luhn reports whether s passes the Luhn checksum used by payment card
// numbers. Spaces and dashes are ignored, so "4111 1111 1111 1111" and
// "5555-5555-5555-4444" are checked on their digits only. Any other
// character, or no digits at all, means s is not a card number.
//
// How Luhn works: starting from the rightmost digit, double every second
// digit; if doubling gives a two-digit number, subtract 9. Add everything up.
// The number is valid when the total is divisible by 10. A random 16-digit
// number passes about 1 time in 10, which is why this check stops most
// order IDs, timestamps and request IDs from being redacted as cards.
//
// Luhn says nothing about length; the credit-card pattern decides that.
func Luhn(s string) bool {
	sum, digits := 0, 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		switch {
		case c == ' ' || c == '-':
			continue
		case c < '0' || c > '9':
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		digits++
		double = !double
	}
	return digits > 0 && sum%10 == 0
}
