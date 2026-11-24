package platformsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf8"
)

func privateFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() > limit {
		return nil, ErrInvalid
	}
	owner, ok := s.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrInvalid
	}
	return b, nil
}

// LoadConfig reads an administrator-provisioned private file. No ambient
// credential store, environment credential, repository config or login is used.
func LoadConfig(path string) (Config, error) {
	var config Config
	b, err := privateFile(path, 32768)
	if err != nil {
		return config, ErrInvalid
	}
	if err := strictJSON(b, &config); err != nil {
		return config, ErrInvalid
	}
	return config, nil
}

// Strict JSON preserves canonical field names and required fields at EVERY
// object, rather than relying on encoding/json's case folding or zero values.
func strictJSON(data []byte, target any) error {
	if !utf8.Valid(data) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return ErrInvalid
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return ErrInvalid
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			return ErrInvalid
		case json.Delim('}'), json.Delim(']'), nil:
			return ErrInvalid
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var actual, expected any
	if json.Unmarshal(data, &actual) != nil || json.Unmarshal(canonical, &expected) != nil {
		return ErrInvalid
	}
	var keys func(any, any) bool
	keys = func(a, b any) bool {
		aa, aok := a.(map[string]any)
		bb, bok := b.(map[string]any)
		if aok != bok {
			return false
		}
		if !aok {
			return true
		}
		if len(aa) != len(bb) {
			return false
		}
		for key, value := range aa {
			other, ok := bb[key]
			if !ok || !keys(value, other) {
				return false
			}
		}
		return true
	}
	if !keys(actual, expected) {
		return errors.New("noncanonical JSON field")
	}
	return nil
}
