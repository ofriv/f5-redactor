package redact

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// TestGeneratedLeakCorpus hides secrets in thousands of generated lines:
// every spelling of a secret field name, in every place a secret can sit
// (JSON at any depth, JSON inside a string, forms, query strings, URLs,
// XML, multipart, free text, headers), plus value-shaped secrets (emails,
// cards, JWTs, API keys) in every string context. Each secret carries a
// unique marker; none may survive redaction.
func TestGeneratedLeakCorpus(t *testing.T) {
	e := shippedEngine(t)
	g := &corpus{}
	g.namedSecrets()
	g.headerSecrets()
	g.shapedSecrets()

	leaks := map[string][]string{} // context -> examples
	for _, c := range g.cases {
		out, _, err := e.RedactLine([]byte(c.line), nil)
		if err != nil {
			t.Fatalf("generated line does not parse (%s): %v\n%s", c.context, err, c.line)
		}
		for _, secret := range c.secrets {
			if strings.Contains(string(out), secret) {
				leaks[c.context] = append(leaks[c.context], c.line)
				break
			}
		}
		// Idempotency on every generated line, too.
		again, _, err := e.RedactLine(out, nil)
		if err != nil || string(again) != string(out) {
			t.Errorf("not idempotent (%s):\n once %s\ntwice %s", c.context, out, again)
		}
	}

	t.Logf("%d generated lines", len(g.cases))
	contexts := make([]string, 0, len(leaks))
	for c := range leaks {
		contexts = append(contexts, c)
	}
	sort.Strings(contexts)
	for _, c := range contexts {
		t.Errorf("%-40s %4d leaks, e.g. %s", c, len(leaks[c]), leaks[c][0])
	}
}

type corpusCase struct {
	context string
	line    string
	secrets []string // substrings that must not appear in the output
}

type corpus struct {
	cases []corpusCase
	n     int
}

func (g *corpus) next() int { g.n++; return g.n }

func (g *corpus) add(context, line string, secrets ...string) {
	g.cases = append(g.cases, corpusCase{context: context, line: line, secrets: secrets})
}

func js(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Every spelling of every secret field name the rules should know.
var secretNames = []string{
	"password", "Password", "PASSWORD", "passwd", "pwd", "passphrase",
	"secret", "client_secret", "clientSecret", "client-secret", "api_secret", "apiSecret",
	"private_key", "privateKey", "token", "access_token", "accessToken", "AccessToken",
	"access-token", "refresh_token", "refreshToken", "id_token", "idToken",
	"auth_token", "authToken", "session_token", "sessionToken", "bearer_token", "bearerToken",
	"api_key", "apiKey", "ApiKey", "api-key", "x-api-key", "X-API-KEY",
}

// namedSecrets: a secret that only its field name identifies.
func (g *corpus) namedSecrets() {
	for _, name := range secretNames {
		v := func() string { return fmt.Sprintf("kv%dzq", g.next()) }
		var s string

		s = v()
		g.add("json body", js(map[string]any{"body": map[string]any{name: s}}), s)
		s = v()
		g.add("json nested", js(map[string]any{"body": map[string]any{"a": []any{map[string]any{"b": map[string]any{name: s}}}}}), s)
		s = v()
		g.add("json response body", js(map[string]any{"response": map[string]any{"body": map[string]any{name: s}}}), s)
		s = v()
		g.add("json unknown top-level field", js(map[string]any{"meta": map[string]any{name: s}}), s)
		s = v()
		g.add("json non-object line", js([]any{map[string]any{name: s}}), s)

		// JSON inside a string, 1 to 5 levels deep.
		for depth := 1; depth <= 5; depth++ {
			s = v()
			doc := js(map[string]any{name: s})
			for range depth - 1 {
				doc = js(map[string]any{"inner": doc})
			}
			g.add(fmt.Sprintf("json in string depth %d", depth), js(map[string]any{"body": doc}), s)
		}
		s = v()
		g.add("broken json in string", js(map[string]any{"body": `{"user":"u",` + js(name) + `:` + js(s)}), s)

		// Forms and URLs.
		s = v()
		g.add("form body with content type", js(map[string]any{
			"headers": map[string]any{"Content-Type": "application/x-www-form-urlencoded"},
			"body":    "a=1&" + url.QueryEscape(name) + "=" + url.QueryEscape(s) + "&b=2"}), s)
		s = v()
		g.add("form body by shape", js(map[string]any{"body": url.QueryEscape(name) + "=" + url.QueryEscape(s) + "&b=2"}), s)
		s = v()
		g.add("query string in path", js(map[string]any{"path": "/x?a=1&" + url.QueryEscape(name) + "=" + url.QueryEscape(s)}), s)
		s = v()
		g.add("url in a field", js(map[string]any{"body": map[string]any{"link": "https://h.example/p?" + url.QueryEscape(name) + "=" + url.QueryEscape(s) + "&x=1"}}), s)

		// Free text, in the forms people write it.
		for _, f := range []struct{ ctx, format string }{
			{"text name=value", "login %s=%s for user"},
			{"text name: value", "cfg %s: %s done"},
			{"text name = value", "cfg %s = %s done"},
			{`text name: "value"`, `cfg %s: "%s" done`},
			{"text name='value'", "cfg %s='%s' done"},
			{"text name=value; next", "a=1; %s=%s; b=2"},
		} {
			s = v()
			g.add(f.ctx, js(map[string]any{"body": map[string]any{"note": fmt.Sprintf(f.format, name, s)}}), s)
		}

		// XML and multipart.
		s = v()
		g.add("xml element", js(map[string]any{"body": "<r><" + name + ">" + s + "</" + name + "></r>"}), s)
		s = v()
		g.add("multipart field", js(map[string]any{"body": "--b\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + s + "\r\n--b--"}), s)

		// The same name used as a header.
		s = v()
		g.add("name as a header", js(map[string]any{"headers": map[string]any{name: s}}), s)
	}
}

// headerSecrets: credentials in headers, including ones not in a fixed list.
func (g *corpus) headerSecrets() {
	headers := []struct{ name, format string }{
		{"Authorization", "Bearer %s"}, {"authorization", "Basic %s"}, {"Proxy-Authorization", "Digest %s"},
		{"X-Auth-Token", "%s"}, {"Cookie", "sid=%s; theme=dark"}, {"Set-Cookie", "sid=%s; HttpOnly"},
		{"X-Api-Key", "%s"}, {"Api-Key", "%s"}, {"X-Access-Token", "%s"}, {"X-CSRF-Token", "%s"},
		{"X-XSRF-TOKEN", "%s"}, {"X-Amz-Security-Token", "%s"}, {"X-Session-Id", "%s"},
		{"X-Client-Secret", "%s"}, {"X-Refresh-Token", "%s"}, {"X-Password", "%s"}, {"X-Goog-Api-Key", "%s"},
	}
	for _, h := range headers {
		s := fmt.Sprintf("hv%dzq", g.next())
		g.add("header "+h.name, js(map[string]any{"headers": map[string]any{h.name: fmt.Sprintf(h.format, s)}}), s)
		s = fmt.Sprintf("hv%dzq", g.next())
		g.add("response header "+h.name, js(map[string]any{"response": map[string]any{"headers": map[string]any{h.name: []any{fmt.Sprintf(h.format, s)}}}}), s)
	}
	// Secrets in URLs inside header values.
	s := fmt.Sprintf("hv%dzq", g.next())
	g.add("referer with token", js(map[string]any{"headers": map[string]any{"Referer": "https://h.example/?token=" + s}}), s)
	s = fmt.Sprintf("hv%dzq", g.next())
	g.add("location with session", js(map[string]any{"response": map[string]any{"headers": map[string]any{"Location": "/home?session=" + s}}}), s)
}

// luhnComplete appends the check digit that makes prefix pass Luhn.
func luhnComplete(prefix string) string {
	for d := '0'; d <= '9'; d++ {
		if c := prefix + string(d); Luhn(c) {
			return c
		}
	}
	panic("unreachable")
}

func jwtFor(n int) string {
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := enc([]byte(fmt.Sprintf(`{"sub":"user-%d","x":"??>>~~"}`, n))) // forces - and _
	sig := enc([]byte(fmt.Sprintf("signature-%d-??>>", n)))
	return header + "." + payload + "." + sig
}

// shapedSecrets: values recognised by their shape, in every string context.
func (g *corpus) shapedSecrets() {
	type shaped struct {
		kind, value string
		secrets     []string
	}
	var values []shaped
	for i, prefix := range []string{"411111111111", "555555555555", "601100000000", "37828224631", "3056930902", "35660020203605"} {
		card := luhnComplete(prefix + fmt.Sprintf("%03d", i))
		visible := card[:len(card)-4]
		spaced := ""
		for j, c := range card {
			if j > 0 && j%4 == 0 {
				spaced += " "
			}
			spaced += string(c)
		}
		dashed := strings.ReplaceAll(spaced, " ", "-")
		values = append(values,
			shaped{"card", card, []string{visible}},
			shaped{"card spaced", spaced, []string{spaced[:len(spaced)-4]}},
			shaped{"card dashed", dashed, []string{dashed[:len(dashed)-4]}},
		)
	}
	for i := range 4 {
		n := g.next()
		values = append(values,
			shaped{"email", fmt.Sprintf("user%d.x+tag@example.co.uk", n), []string{fmt.Sprintf("user%d.x+tag@example", n)}},
			shaped{"email encoded", fmt.Sprintf("user%d%%40example.com", n), []string{fmt.Sprintf("user%d%%40example", n)}},
			shaped{"jwt", jwtFor(n), strings.Split(jwtFor(n), ".")},
			shaped{"api key", fmt.Sprintf("sk_live_%dAbC%d", n, i), []string{fmt.Sprintf("sk_live_%dAbC%d", n, i)}},
		)
	}

	for _, v := range values {
		contexts := []struct {
			ctx  string
			line string
		}{
			{"value in json field", js(map[string]any{"body": map[string]any{"note": v.value}})},
			{"value in free text", js(map[string]any{"body": map[string]any{"note": "see " + v.value + " now."}})},
			{"value in plain text body", js(map[string]any{"body": "Hi,\n" + v.value + "\nthanks"})},
			{"value in json in string", js(map[string]any{"body": js(map[string]any{"x": map[string]any{"y": v.value}})})},
			{"value in form", js(map[string]any{"body": "a=1&c=" + url.QueryEscape(v.value)})},
			{"value in query string", js(map[string]any{"path": "/x?c=" + url.QueryEscape(v.value)})},
			{"value in xml", js(map[string]any{"body": "<note>" + v.value + "</note>"})},
			{"value in a header", js(map[string]any{"headers": map[string]any{"X-Note": v.value}})},
			{"value as an object key", js(map[string]any{"body": map[string]any{v.value: 1}})},
			{"value in a non-object line", js([]any{v.value})},
			{"value in response body string", js(map[string]any{"response": map[string]any{"body": "err for " + v.value}})},
		}
		for _, c := range contexts {
			g.add(v.kind+": "+c.ctx, c.line, v.secrets...)
		}
	}
}
