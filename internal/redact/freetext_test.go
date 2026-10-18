package redact

import (
	"maps"
	"testing"
)

// Secrets written as name=value inside free text (input line 41).
func TestSecretAssignmentInText(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct {
		in, want string
	}{
		{"login attempt password=hunter2 for user=zed", "login attempt **** for user=zed"},
		{"retry with token: abc123, then stop", "retry with ****, then stop"},
		{"PASSWORD = hunter2", "****"},
		{"cfg api_key=k1;secret=s2", "cfg ****;****"},
		{`json "password":"x" is not this rule`, `json "password":"x" is not this rule`},
		{"password_hint=first pet", "password_hint=first pet"},
		{"mypassword=x", "mypassword=x"},
		{"no secret here", "no secret here"},
	}
	for _, tt := range tests {
		if got := e.RedactText(tt.in, nil); got != tt.want {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", tt.in, got, tt.want)
		}
	}
}

// Personal data fields (input line 37) are hashed; the name stays.
func TestPIIFields(t *testing.T) {
	e := shippedEngine(t)
	in := `{"body":{"ssn":"123-45-6789","phone":"+1 (415) 555-0132","dob":"1990-04-12","name":"Ivy Chen"}}`
	want := `{"body":{"ssn":"` + Hash("123-45-6789") + `","phone":"` + Hash("+1 (415) 555-0132") + `","dob":"` + Hash("1990-04-12") + `","name":"Ivy Chen"}}`
	got, counts := redactLine(t, e, in)
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if !maps.Equal(counts, Counts{"pii-fields": 3}) {
		t.Errorf("counts = %v", counts)
	}
}
