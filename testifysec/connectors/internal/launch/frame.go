package launch

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ErrRepeatedKey and ErrTooDeep are why a plugin frame is refused by both the host's scrub and the
// gateway: two parsers could read different values from a repeated key, and unbounded nesting
// would cost memory before any check ends.
var (
	ErrRepeatedKey = errors.New("a JSON object repeats a key")
	ErrTooDeep     = errors.New("JSON nested deeper than 64 levels")
)

// MaxJSONDepth bounds nesting in a plugin frame; MCP frames use a handful of levels.
const MaxJSONDepth = 64

// JSONStrings calls fn for every object key and every string value in b, in order, duplicates
// included, without building a map that would keep only one of a repeated key. It reports whether
// b is exactly one JSON value, and why it must be refused: ErrRepeatedKey when an object repeats a
// key at any depth (the walk still visits every string), or ErrTooDeep, where it stops before
// allocating another level.
func JSONStrings(b []byte, fn func(string)) (valid bool, refuse error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	type level struct {
		object    bool
		expectKey bool
		keys      map[string]bool
	}
	var stack []*level
	value := func() { // a value ends at the current level: an object then wants its next key
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	started := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return started && len(stack) == 0, refuse
		}
		if err != nil {
			return false, refuse
		}
		if started && len(stack) == 0 {
			return false, refuse // a second value after the first
		}
		started = true
		top := (*level)(nil)
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= MaxJSONDepth {
					return true, ErrTooDeep
				}
				if top != nil && top.object {
					top.expectKey = false
				}
				stack = append(stack, &level{object: t == '{', expectKey: t == '{', keys: map[string]bool{}})
			case '}', ']':
				stack = stack[:len(stack)-1]
				value()
			}
		case string:
			fn(t)
			if top != nil && top.object && top.expectKey {
				if top.keys[t] {
					refuse = ErrRepeatedKey
				}
				top.keys[t] = true
				top.expectKey = false
			} else {
				value()
			}
		default:
			value()
		}
	}
}
