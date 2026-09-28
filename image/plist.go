// A minimal reader for Apple XML property lists — the shape UDIF (.dmg)
// images carry their block tables in, and .sparsebundle directories their
// geometry. Only what those need: dict, array, string, data, integer,
// true/false (real and date are kept as their text). Written from Apple's
// public PropertyList-1.0 DTD; gomount's own code.
package image

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// plistMaxDepth bounds nesting so a hostile plist cannot exhaust the stack.
const plistMaxDepth = 32

type plistValue struct {
	kind string // "dict" | "array" | "string" | "data" | "integer" | "true" | "false" | "real" | "date"
	text string
	data []byte
	dict map[string]*plistValue
	arr  []*plistValue
}

// get returns the value under key of a dict (nil for a missing key or a
// non-dict receiver).
func (v *plistValue) get(key string) *plistValue {
	if v == nil || v.kind != "dict" {
		return nil
	}
	return v.dict[key]
}

// uint parses an <integer> (or a <string> holding one, as older bundles
// wrote) as an unsigned decimal.
func (v *plistValue) uint() (uint64, bool) {
	if v == nil || (v.kind != "integer" && v.kind != "string") {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(v.text), 10, 64)
	return n, err == nil
}

// parsePlist decodes an XML property list and returns its top-level value.
func parsePlist(r io.Reader) (*plistValue, error) {
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("plist: no <plist> element")
			}
			return nil, fmt.Errorf("plist: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local != "plist" {
			return nil, fmt.Errorf("plist: root element <%s>, want <plist>", se.Name.Local)
		}
		// the first element inside <plist> is the value
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("plist: %w", err)
			}
			switch t := tok.(type) {
			case xml.StartElement:
				return plistParseValue(dec, t, 0)
			case xml.EndElement:
				return nil, errors.New("plist: empty <plist>")
			}
		}
	}
}

func plistParseValue(dec *xml.Decoder, se xml.StartElement, depth int) (*plistValue, error) {
	if depth > plistMaxDepth {
		return nil, errors.New("plist: nested too deeply")
	}
	v := &plistValue{kind: se.Name.Local}
	switch v.kind {
	case "dict":
		v.dict = map[string]*plistValue{}
		key, haveKey := "", false
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("plist: dict: %w", err)
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					if key, err = plistText(dec); err != nil {
						return nil, err
					}
					haveKey = true
					continue
				}
				if !haveKey {
					return nil, fmt.Errorf("plist: dict value <%s> without a key", t.Name.Local)
				}
				child, err := plistParseValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				v.dict[key] = child
				haveKey = false
			case xml.EndElement:
				return v, nil
			}
		}
	case "array":
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("plist: array: %w", err)
			}
			switch t := tok.(type) {
			case xml.StartElement:
				child, err := plistParseValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				v.arr = append(v.arr, child)
			case xml.EndElement:
				return v, nil
			}
		}
	case "data":
		s, err := plistText(dec)
		if err != nil {
			return nil, err
		}
		s = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, s)
		if v.data, err = base64.StdEncoding.DecodeString(s); err != nil {
			return nil, fmt.Errorf("plist: <data>: %w", err)
		}
		return v, nil
	case "string", "integer", "real", "date", "true", "false":
		s, err := plistText(dec)
		if err != nil {
			return nil, err
		}
		v.text = s
		return v, nil
	default:
		return nil, fmt.Errorf("plist: unknown element <%s>", v.kind)
	}
}

// plistText collects the character data of a leaf element up to its end tag.
func plistText(dec *xml.Decoder) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
		case xml.StartElement:
			return "", fmt.Errorf("plist: unexpected <%s> inside a leaf", t.Name.Local)
		case xml.EndElement:
			return b.String(), nil
		}
	}
}
