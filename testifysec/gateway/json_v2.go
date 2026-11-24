package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"unicode/utf8"
)

// V2 accepts only the exact typed contract, including nested field spelling,
// required values and canonical nonnegative integers. V1 parsing is unchanged.
func strictV2(raw []byte, target any) error { return strictTyped(raw, target, nil) }

// strictTyped is strictV2 where a field at a path in nullable (dot-separated object keys; arrays
// add nothing, so "profile.connectors.caPath") may also be null. No other null is accepted, so a
// nil slice, a missing field, or a same-named key elsewhere is still refused.
func strictTyped(raw []byte, target any, nullable map[string]bool) error {
	if len(raw) > 32768 || !validV2Unicode(raw) {
		return errors.New("invalid v2 JSON encoding or size")
	}
	if err := strictJSON(raw, target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var actual, expected any
	for _, item := range []struct {
		raw    []byte
		target *any
	}{{raw, &actual}, {canonical, &expected}} {
		decoder := json.NewDecoder(bytes.NewReader(item.raw))
		decoder.UseNumber()
		if err = decoder.Decode(item.target); err != nil {
			return err
		}
	}
	if !typedShape(actual, expected, nullable, "") {
		return errors.New("noncanonical v2 JSON fields or values")
	}
	return nil
}

func typedShape(actual, expected any, nullable map[string]bool, key string) bool {
	if nullable[key] && actual == nil {
		return true
	}
	switch value := expected.(type) {
	case map[string]any:
		object, ok := actual.(map[string]any)
		if !ok || len(object) != len(value) {
			return false
		}
		for name, child := range value {
			at := name
			if key != "" {
				at = key + "." + name
			}
			if _, present := object[name]; !present || !typedShape(object[name], child, nullable, at) {
				return false
			}
		}
		return true
	case []any:
		array, ok := actual.([]any)
		if !ok || len(array) != len(value) {
			return false
		}
		for index, child := range value {
			if !typedShape(array[index], child, nullable, key) {
				return false
			}
		}
		return true
	case string:
		_, ok := actual.(string)
		return ok
	case bool:
		_, ok := actual.(bool)
		return ok
	case json.Number:
		number, ok := actual.(json.Number)
		return ok && regexp.MustCompile(`^(0|[1-9][0-9]*)$`).MatchString(string(number))
	default:
		return false
	}
}

// encoding/json replaces lone surrogate escapes; authority-bearing JSON must
// reject them before decoding instead of silently changing a string.
func validV2Unicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	inside := false
	for index := 0; index < len(raw); index++ {
		if raw[index] == '"' {
			inside = !inside
			continue
		}
		if !inside || raw[index] != '\\' {
			continue
		}
		index++
		if index >= len(raw) {
			return false
		}
		if raw[index] != 'u' {
			continue
		}
		if index+4 >= len(raw) {
			return false
		}
		digits, err := hex.DecodeString(string(raw[index+1 : index+5]))
		if err != nil {
			return false
		}
		code := uint16(digits[0])<<8 | uint16(digits[1])
		index += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
			return false
		}
		low, err := hex.DecodeString(string(raw[index+3 : index+7]))
		if err != nil {
			return false
		}
		part := uint16(low[0])<<8 | uint16(low[1])
		if part < 0xdc00 || part > 0xdfff {
			return false
		}
		index += 6
	}
	return true
}
