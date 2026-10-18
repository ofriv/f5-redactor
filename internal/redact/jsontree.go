package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

// maxDepth limits how deeply objects and arrays may nest. Real API payloads
// stay far below it (the deepest sample line has 12 levels); a line that
// goes deeper is rejected instead of risking unbounded recursion. Go stacks
// grow as needed, so 1000 levels of recursion are cheap.
const maxDepth = 1000

// maxValues limits how many JSON values (strings, numbers, objects, ...) one
// line may hold. Each value becomes a tree node of about 100 bytes, so a
// 10 MiB line of "[1,1,1,...]" (5 million values) would need over 500 MiB.
// 200,000 values caps that at about 20 MiB per line, far above what a real
// API transaction holds. A line over the limit is rejected like a too-long
// line.
const maxValues = 200_000

var (
	// ErrEmpty means the line holds only whitespace.
	ErrEmpty = errors.New("empty_line")
	// ErrInvalidJSON means the line is not one complete JSON value.
	ErrInvalidJSON = errors.New("invalid_json")
	// ErrTooDeep means the line nests deeper than maxDepth.
	ErrTooDeep = errors.New("too_deep")
	// ErrTooManyValues means the line holds more than maxValues values.
	ErrTooManyValues = errors.New("too_many_values")
)

// Why not decode into map[string]any? A Go map drops duplicate keys (line 25
// has "email" twice, and the second one would silently win), loses key order,
// and turns numbers into float64, which corrupts 12345678901234567890 and
// rewrites 1.0 as 1. This small tree keeps the document exactly as written.

type kind uint8

const (
	kindNull kind = iota
	kindBool
	kindNumber // text holds the literal exactly as it appeared, e.g. "1e3"
	kindString // text holds the decoded string
	kindArray
	kindObject
)

type node struct {
	kind    kind
	text    string
	boolean bool
	items   []*node  // kindArray
	members []member // kindObject, in input order, duplicates kept
}

type member struct {
	key   string
	value *node
}

// parseJSON parses exactly one JSON value. Errors are the fixed values above
// and never include the decoder's message, because that message can quote
// the input, and the input may be sensitive.
func parseJSON(data []byte) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	tok, err := dec.Token()
	if errors.Is(err, io.EOF) {
		return nil, ErrEmpty
	}
	if err != nil {
		return nil, ErrInvalidJSON
	}
	values := 0
	n, err := parseFrom(dec, tok, 0, &values)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidJSON // something after the value
	}
	return n, nil
}

func parseFrom(dec *json.Decoder, tok json.Token, depth int, values *int) (*node, error) {
	if *values++; *values > maxValues {
		return nil, ErrTooManyValues
	}
	switch v := tok.(type) {
	case nil:
		return &node{kind: kindNull}, nil
	case bool:
		return &node{kind: kindBool, boolean: v}, nil
	case json.Number:
		return &node{kind: kindNumber, text: string(v)}, nil
	case string:
		return &node{kind: kindString, text: v}, nil
	case json.Delim:
		if depth >= maxDepth {
			return nil, ErrTooDeep
		}
		if v == '{' {
			return parseObject(dec, depth, values)
		}
		if v == '[' {
			return parseArray(dec, depth, values)
		}
	}
	return nil, ErrInvalidJSON
}

func parseObject(dec *json.Decoder, depth int, values *int) (*node, error) {
	n := &node{kind: kindObject}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, ErrInvalidJSON
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, ErrInvalidJSON
		}
		value, err := parseNext(dec, depth+1, values)
		if err != nil {
			return nil, err
		}
		n.members = append(n.members, member{key: key, value: value})
	}
	if _, err := dec.Token(); err != nil { // the closing '}'
		return nil, ErrInvalidJSON
	}
	return n, nil
}

func parseArray(dec *json.Decoder, depth int, values *int) (*node, error) {
	n := &node{kind: kindArray}
	for dec.More() {
		item, err := parseNext(dec, depth+1, values)
		if err != nil {
			return nil, err
		}
		n.items = append(n.items, item)
	}
	if _, err := dec.Token(); err != nil { // the closing ']'
		return nil, ErrInvalidJSON
	}
	return n, nil
}

func parseNext(dec *json.Decoder, depth int, values *int) (*node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return parseFrom(dec, tok, depth, values)
}

// appendJSON writes n as compact JSON. Writing it by hand (instead of with
// encoding/json) keeps number literals and key order untouched, and leaves
// characters such as <, > and & as they are; encoding/json would turn "&"
// into "&" by default.
func appendJSON(buf []byte, n *node) []byte {
	switch n.kind {
	case kindNull:
		return append(buf, "null"...)
	case kindBool:
		return strconv.AppendBool(buf, n.boolean)
	case kindNumber:
		return append(buf, n.text...)
	case kindString:
		return appendString(buf, n.text)
	case kindArray:
		buf = append(buf, '[')
		for i, item := range n.items {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendJSON(buf, item)
		}
		return append(buf, ']')
	default: // kindObject
		buf = append(buf, '{')
		for i, m := range n.members {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendString(buf, m.key)
			buf = append(buf, ':')
			buf = appendJSON(buf, m.value)
		}
		return append(buf, '}')
	}
}

// appendString writes s as a JSON string literal. Only the characters JSON
// requires to be escaped are escaped; everything else, including non-ASCII
// text, is written as UTF-8.
func appendString(buf []byte, s string) []byte {
	const hex = "0123456789abcdef"
	buf = append(buf, '"')
	for _, r := range s {
		switch {
		case r == '"':
			buf = append(buf, '\\', '"')
		case r == '\\':
			buf = append(buf, '\\', '\\')
		case r == '\n':
			buf = append(buf, '\\', 'n')
		case r == '\r':
			buf = append(buf, '\\', 'r')
		case r == '\t':
			buf = append(buf, '\\', 't')
		case r < 0x20:
			buf = append(buf, '\\', 'u', '0', '0', hex[r>>4], hex[r&0xf])
		default:
			buf = utf8.AppendRune(buf, r) // invalid UTF-8 becomes U+FFFD
		}
	}
	return append(buf, '"')
}
