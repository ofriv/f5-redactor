package redact

import (
	"net/url"
	"strings"

	"f5-redactor/internal/config"
)

// maxEmbedDepth limits JSON inside a string inside JSON. Three levels covers
// real double-encoded payloads; past that the string is still scanned with
// the value rules, only key rules are not applied.
const maxEmbedDepth = 3

// redactBodyString redacts a string found in a body. The string may be a
// document of its own, so it is tried, in order, as:
//
//  1. JSON: a string that starts with { or [ and parses is redacted like a
//     body, so key rules apply inside it (line 10: "password" inside a
//     JSON string). If nothing inside needed redacting, the original string
//     is kept as is, formatting included.
//  2. A form (key=value&key=value): when the Content-Type says so, or when
//     the string has the shape of one. Key rules apply to field names, value
//     rules to the decoded values (line 8: "bob%40example.com").
//  3. Plain text: value rules only.
//
// Anything that fails to parse falls through to the next step, so a broken
// document is still scanned as text.
func (e *Engine) redactBodyString(s string, w walk, counts Counts) string {
	if w.embedDepth < maxEmbedDepth && looksLikeJSON(s) {
		if root, err := parseJSON([]byte(s)); err == nil && (root.kind == kindObject || root.kind == kindArray) {
			local := Counts{}
			e.redactNode(root, walk{where: config.ScopeBody, embedDepth: w.embedDepth + 1}, local)
			if len(local) == 0 {
				return s
			}
			counts.merge(local)
			return string(appendJSON(nil, root))
		}
	}
	if isFormContentType(w.contentType) || looksLikeForm(s) {
		return e.redactForm(s, config.ScopeBody, counts)
	}
	return e.RedactText(s, counts)
}

// redactPath redacts the "path" of a transaction. The part before "?" is
// text; the query string is redacted like a form, with the body's key rules
// (a query parameter is a request field just like a form field, so
// token=abc123 is caught by the secret-fields rule).
func (e *Engine) redactPath(path string, counts Counts) string {
	base, query, hasQuery := strings.Cut(path, "?")
	base = e.RedactText(base, counts)
	if !hasQuery {
		return base
	}
	query, fragment, hasFragment := strings.Cut(query, "#")
	out := base + "?" + e.redactForm(query, config.ScopeBody, counts)
	if hasFragment {
		out += "#" + e.RedactText(fragment, counts)
	}
	return out
}

// redactForm redacts a URL-encoded form or query string. Pairs that do not
// change are copied byte for byte; only changed parts are encoded again, so
// the output stays readable ("password=****", not "password=%2A%2A%2A%2A")
// and a second run changes nothing.
func (e *Engine) redactForm(form string, where config.Scope, counts Counts) string {
	pairs := strings.Split(form, "&")
	kept := pairs[:0]
	for _, pair := range pairs {
		rawKey, rawValue, hasValue := strings.Cut(pair, "=")
		key, errKey := url.QueryUnescape(rawKey)
		value, errValue := url.QueryUnescape(rawValue)
		if errKey != nil || errValue != nil {
			// Broken percent-encoding: treat the pair as plain text.
			kept = append(kept, e.RedactText(pair, counts))
			continue
		}

		newValue := value
		rule := e.keyRuleFor(key, where)
		switch {
		case rule != nil && rule.Action == config.ActionRemove:
			counts.add(rule.Name)
			continue // drop the pair
		case rule != nil:
			newValue = e.applyKeyRule(rule, value)
			if newValue != value {
				counts.add(rule.Name)
			}
		default:
			newValue = e.RedactText(value, counts)
		}
		newKey := e.RedactText(key, counts)

		if newKey != key {
			rawKey = escapeFormComponent(newKey)
		}
		if newValue != value {
			rawValue = escapeFormComponent(newValue)
		}
		if hasValue || newValue != "" {
			kept = append(kept, rawKey+"="+rawValue)
		} else {
			kept = append(kept, rawKey)
		}
	}
	return strings.Join(kept, "&")
}

// escapeFormComponent percent-encodes only what would change the meaning of
// a form: the separators & = + # %, spaces, control characters and
// non-ASCII bytes. Everything else (letters, digits, * : - _ . ~ and so on)
// is written as is.
func escapeFormComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '&' || c == '=' || c == '+' || c == '#' || c == '%' || c <= ' ' || c >= 0x7f:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// looksLikeJSON reports whether s starts (after spaces) like a JSON object or
// array. It only decides whether parsing is worth trying.
func looksLikeJSON(s string) bool {
	s = strings.TrimLeft(s, " \t\r\n")
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

// looksLikeForm reports whether s has the shape of a URL-encoded form: no
// whitespace, and a first pair of the form name=value. Free text such as
// "login attempt password=hunter2" has spaces and is not a form.
func looksLikeForm(s string) bool {
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	first, _, _ := strings.Cut(s, "&")
	name, _, hasValue := strings.Cut(first, "=")
	return hasValue && name != ""
}

// isFormContentType reports whether a Content-Type header names a form.
func isFormContentType(ct string) bool {
	mediaType, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/x-www-form-urlencoded")
}

// contentTypeOf returns the Content-Type from a transaction's (or a
// response's) headers, or "". Header names are matched case-insensitively,
// and a header given as an array uses its first value.
func contentTypeOf(tx *node) string {
	for _, m := range tx.members {
		if m.key != "headers" || m.value.kind != kindObject {
			continue
		}
		for _, h := range m.value.members {
			if !strings.EqualFold(h.key, "Content-Type") {
				continue
			}
			switch v := h.value; {
			case v.kind == kindString:
				return v.text
			case v.kind == kindArray && len(v.items) > 0 && v.items[0].kind == kindString:
				return v.items[0].text
			}
		}
	}
	return ""
}
