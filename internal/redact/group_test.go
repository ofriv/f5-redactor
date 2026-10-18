package redact

import (
	"maps"
	"testing"
)

// Secrets in XML and multipart bodies: only the value is masked.
func TestXMLAndMultipartSecrets(t *testing.T) {
	e := shippedEngine(t)
	tests := []struct {
		name, in, want string
		counts         Counts
	}{
		{
			name:   "xml element",
			in:     `<login><user>dan</user><password>xml-pw-1</password></login>`,
			want:   `<login><user>dan</user><password>****</password></login>`,
			counts: Counts{"xml-secret": 1},
		},
		{
			name:   "xml with namespace and attribute",
			in:     `<a:accessToken type="opaque">xml-at-2</a:accessToken>`,
			want:   `<a:accessToken type="opaque">****</a:accessToken>`,
			counts: Counts{"xml-secret": 1},
		},
		{
			name:   "xml look-alike is left alone",
			in:     `<password_hint>first pet</password_hint>`,
			want:   `<password_hint>first pet</password_hint>`,
			counts: Counts{},
		},
		{
			name:   "multipart field",
			in:     "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nmp-pw-3\r\n--b--",
			want:   "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n****\r\n--b--",
			counts: Counts{"multipart-secret": 1},
		},
		{
			name:   "multipart field with its own content type",
			in:     "--b\r\nContent-Disposition: form-data; name=\"apiKey\"\r\nContent-Type: text/plain\r\n\r\nmp-key-4\r\n--b--",
			want:   "--b\r\nContent-Disposition: form-data; name=\"apiKey\"\r\nContent-Type: text/plain\r\n\r\n****\r\n--b--",
			counts: Counts{"multipart-secret": 1},
		},
		{
			name:   "json text",
			in:     `log: {"user":"dan","clientSecret":"js-5"`,
			want:   `log: {"user":"dan","clientSecret":"****"`,
			counts: Counts{"json-secret": 1},
		},
		{
			name:   "json text with an empty value",
			in:     `{"password":""`,
			want:   `{"password":""`,
			counts: Counts{},
		},
		{
			name:   "encoded email in text",
			in:     "contact bob%40example.com today",
			want:   "contact " + Hash("bob%40example.com") + " today",
			counts: Counts{"email": 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counts := Counts{}
			got := e.RedactText(tt.in, counts)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
			if !maps.Equal(counts, tt.counts) {
				t.Errorf("counts = %v, want %v", counts, tt.counts)
			}
			if again := e.RedactText(got, nil); again != got {
				t.Errorf("not idempotent: %q", again)
			}
		})
	}
}
