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
		// Only the value is masked; the name stays (group: 1).
		{"login attempt password=hunter2 for user=zed", "login attempt password=**** for user=zed"},
		{"retry with token: abc123, then stop", "retry with token: ****, then stop"},
		{"PASSWORD = hunter2", "PASSWORD = ****"},
		{"cfg api_key=k1;secret=s2", "cfg api_key=****;secret=****"},
		{"auth token: Bearer abc123", "auth token: Bearer ****"},
		{"password=****", "password=****"},
		// JSON syntax in text is the json-secret rule's job.
		{`json "password":"x" in text`, `json "password":"****" in text`},
		{"password_hint=first pet", "password_hint=first pet"},
		// A name that ends with a secret word is a secret name.
		{"mypassword=x", "mypassword=****"},
		{"debug db_password=Hunter2 AWS_SECRET_ACCESS_KEY=abcd1234", "debug db_password=**** AWS_SECRET_ACCESS_KEY=****"},
		{"password_hint=first", "password_hint=first"},
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
