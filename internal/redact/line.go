package redact

import (
	"regexp"
	"strings"

	"f5-redactor/internal/config"
)

// NoticeNotObject is reported for a line that is valid JSON but not an
// object (e.g. `42` or `["a@b.com"]`). The line is still redacted, with every
// key rule, so no data is lost and none leaks.
const NoticeNotObject = "not_an_object"

// Scopes used inside the engine, next to config.ScopeHeaders and
// config.ScopeBody.
//
// The scope of a key rule tells apart two kinds of names: HTTP header names
// ("headers") and JSON field names ("body"). So any JSON field outside
// headers is treated as body: a password inside an unexpected top-level
// field ({"user":{"password":...}}) is still a JSON field named password.
const (
	// scopeTop is the top level of a transaction (or of its response),
	// where headers, body, response and path have their own handling.
	// Every other field there is redacted as body.
	scopeTop config.Scope = "top"
	// scopeUnknown is a value whose structure we do not know (a line that
	// is not an object): every key rule applies, whatever its scope.
	scopeUnknown config.Scope = "unknown"
)

// integerLiteral matches JSON numbers that could be an ID or a card number.
var integerLiteral = regexp.MustCompile(`^-?[0-9]+$`)

// RedactLine redacts one NDJSON line (without its newline) and returns the
// redacted JSON. Redactions are added to counts.
//
// On error the line could not be parsed and nothing should be written from
// it; the error is one of ErrEmpty, ErrInvalidJSON or ErrTooDeep and never
// contains input data. notice is non-empty for a line that was redacted but
// is unusual (see NoticeNotObject).
func (e *Engine) RedactLine(line []byte, counts Counts) (out []byte, notice string, err error) {
	root, err := parseJSON(line)
	if err != nil {
		return nil, "", err
	}
	if root.kind == kindObject {
		e.redactObject(root, walk{where: scopeTop}, counts)
	} else {
		e.redactNode(root, walk{where: scopeUnknown}, counts)
		notice = NoticeNotObject
	}
	return appendJSON(make([]byte, 0, len(line)), root), notice, nil
}

// walk is the context of the value being redacted.
type walk struct {
	// where is the part of the transaction (top, headers, body or
	// unknown), which decides the key rules that apply.
	where config.Scope
	// embedDepth counts how many JSON-inside-a-string levels we are in.
	embedDepth int
	// contentType is set only for the body value itself, from the matching
	// headers. It helps recognise a form body.
	contentType string
}

// redactObject redacts every member of an object.
func (e *Engine) redactObject(obj *node, w walk, counts Counts) {
	inner := walk{where: w.where, embedDepth: w.embedDepth}

	var contentType string
	if w.where == scopeTop {
		contentType = contentTypeOf(obj)
	}

	kept := obj.members[:0]
	for _, m := range obj.members {
		if w.where == scopeTop {
			// The transaction's structure: headers and body switch scope,
			// the response holds its own headers and body, and the path may
			// carry a query string.
			switch {
			case m.key == "headers":
				e.redactNode(m.value, walk{where: config.ScopeHeaders, embedDepth: w.embedDepth}, counts)
				kept = append(kept, m)
				continue
			case m.key == "body":
				e.redactNode(m.value, walk{where: config.ScopeBody, embedDepth: w.embedDepth, contentType: contentType}, counts)
				kept = append(kept, m)
				continue
			case m.key == "response" && m.value.kind == kindObject:
				e.redactObject(m.value, inner, counts)
				kept = append(kept, m)
				continue
			case m.key == "path" && m.value.kind == kindString:
				m.value.text = e.redactPath(m.value.text, counts)
				kept = append(kept, m)
				continue
			}
		}

		field := inner
		if w.where == scopeTop {
			field.where = config.ScopeBody // any other top-level field
		}
		rule := e.keyRuleFor(m.key, field.where)
		switch {
		case rule == nil:
			e.redactNode(m.value, field, counts)
		case rule.Action == config.ActionRemove:
			counts.add(rule.Name)
			continue // drop the key and its value
		default:
			e.redactWithKeyRule(rule, m.value, counts)
		}
		// Value rules also apply to key names: objects keyed by email
		// address ({"alice@example.com": {...}}) are common.
		m.key = e.RedactText(m.key, counts)
		kept = append(kept, m)
	}
	obj.members = kept
}

// keyRuleFor returns the first key rule that covers key in this scope, or nil.
// Rules are tried in the order they appear in rules.yaml. In scopeUnknown
// every rule applies.
func (e *Engine) keyRuleFor(key string, where config.Scope) *config.KeyRule {
	for i := range e.keyRules {
		r := &e.keyRules[i]
		if (where == scopeUnknown || r.AppliesTo(where)) && r.Matches(key) {
			return r
		}
	}
	return nil
}

// redactNode applies the value rules to every string (and integer) inside n.
// Strings in a body may hold a whole document of their own (JSON or a form),
// see redactBodyString.
func (e *Engine) redactNode(n *node, w walk, counts Counts) {
	switch n.kind {
	case kindString:
		if w.where == config.ScopeBody || w.where == scopeUnknown {
			n.text = e.redactBodyString(n.text, w, counts)
		} else {
			n.text = e.RedactText(n.text, counts)
		}
	case kindNumber:
		// A card number can arrive as a JSON number ("ref": 4111111111111111).
		// If a value rule changes it, the result is written as a string.
		if integerLiteral.MatchString(n.text) {
			if redacted := e.RedactText(n.text, counts); redacted != n.text {
				n.kind, n.text = kindString, redacted
			}
		}
	case kindArray:
		inner := walk{where: w.where, embedDepth: w.embedDepth}
		for _, item := range n.items {
			e.redactNode(item, inner, counts)
		}
	case kindObject:
		e.redactObject(n, w, counts)
	}
}

// redactWithKeyRule applies a key rule to the value of a matching key.
//
//   - null and "" are left alone: there is nothing to hide.
//   - Numbers and booleans are redacted through their text and become
//     strings ("api_key": 0 is hashed, "token": false is masked).
//   - Inside an object or array, the rule applies to every value, and the
//     structure (and the inner key names) is kept.
func (e *Engine) redactWithKeyRule(rule *config.KeyRule, n *node, counts Counts) {
	var text string
	switch n.kind {
	case kindNull:
		return
	case kindString:
		text = n.text
	case kindNumber:
		text = n.text
	case kindBool:
		text = "false"
		if n.boolean {
			text = "true"
		}
	case kindArray:
		for _, item := range n.items {
			e.redactWithKeyRule(rule, item, counts)
		}
		return
	case kindObject:
		for _, m := range n.members {
			e.redactWithKeyRule(rule, m.value, counts)
		}
		return
	}

	redacted := e.applyKeyRule(rule, text)
	if n.kind != kindString || redacted != text {
		counts.add(rule.Name)
	}
	n.kind, n.text = kindString, redacted
}

// applyKeyRule runs the rule's action on one value, keeping the auth scheme
// in front when the rule asks for it.
func (e *Engine) applyKeyRule(rule *config.KeyRule, v string) string {
	if rule.PreserveScheme {
		if scheme, credential, ok := splitAuthScheme(v); ok {
			return scheme + " " + e.actions.Apply(rule.Action, credential)
		}
	}
	return e.actions.Apply(rule.Action, v)
}

// authSchemes are the HTTP authentication schemes kept by preserve_scheme
// (the IANA registry plus common non-registered ones). Only known names are
// kept: treating any first word as a scheme would leak the start of a value
// like "my secret password".
var authSchemes = map[string]bool{
	"basic": true, "bearer": true, "digest": true, "dpop": true,
	"hoba": true, "mutual": true, "negotiate": true, "ntlm": true,
	"privatetoken": true, "scram-sha-1": true, "scram-sha-256": true,
	"vapid": true, "aws4-hmac-sha256": true, "token": true, "apikey": true,
}

// splitAuthScheme splits "Bearer abc" into ("Bearer", "abc"). It reports
// false when v does not start with a known scheme followed by a credential.
func splitAuthScheme(v string) (scheme, credential string, ok bool) {
	scheme, rest, found := strings.Cut(v, " ")
	if !found || !authSchemes[strings.ToLower(scheme)] {
		return "", "", false
	}
	credential = strings.TrimLeft(rest, " ")
	if credential == "" {
		return "", "", false
	}
	return scheme, credential, true
}
