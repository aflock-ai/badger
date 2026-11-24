package vzsession

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"unicode/utf8"
)

func walkJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON depth")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			name, ok := key.(string)
			if !ok || seen[name] || len(seen) >= 64 {
				return errors.New("JSON keys")
			}
			seen[name] = true
			if e = walkJSON(d, depth+1); e != nil {
				return e
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for count := 0; d.More(); count++ {
			if count >= 64 {
				return errors.New("JSON array")
			}
			if err = walkJSON(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}

// Exact typed shape and original number tokens must survive decoding. This
// rejects duplicate/escaped aliases, unknown/missing fields, null coercions and
// case-insensitive struct aliases before any claim is used.
func strict(raw []byte, target any) error {
	if !validUnicode(raw) {
		return errors.New("JSON encoding")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := walkJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("JSON trailing")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var original, normalized any
	for _, pair := range []struct {
		raw   []byte
		value *any
	}{{raw, &original}, {encoded, &normalized}} {
		d = json.NewDecoder(bytes.NewReader(pair.raw))
		d.UseNumber()
		if err = d.Decode(pair.value); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(original, normalized) {
		return errors.New("JSON exact shape")
	}
	return nil
}

// encoding/json deliberately replaces invalid surrogate escapes. Admission must
// reject them, rather than silently changing a command or policy path.
func validUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	inside := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		end, ok := unicodeEnd(raw, i)
		if !ok {
			return false
		}
		i = end
	}
	return true
}
func unicodeUnit(raw []byte, start int) (uint16, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	digits, err := hex.DecodeString(string(raw[start : start+4]))
	if err != nil {
		return 0, false
	}
	return uint16(digits[0])<<8 | uint16(digits[1]), true
}
func unicodeEnd(raw []byte, index int) (int, bool) {
	code, ok := unicodeUnit(raw, index+1)
	if !ok || code >= 0xdc00 && code <= 0xdfff {
		return 0, false
	}
	index += 4
	if code < 0xd800 || code > 0xdbff {
		return index, true
	}
	if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
		return 0, false
	}
	low, ok := unicodeUnit(raw, index+3)
	if !ok || low < 0xdc00 || low > 0xdfff {
		return 0, false
	}
	return index + 6, true
}
