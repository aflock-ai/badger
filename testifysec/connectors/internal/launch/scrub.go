//go:build unix

package launch

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
)

// ErrTokenInOutput ends a stream whose plugin wrote its own service token.
var ErrTokenInOutput = errors.New("plugin output carried its service token; stream ended")

// MinToken is the shortest service token the host accepts. Every encoded form of a token this long
// is long enough to match without ending clean streams, so none is skipped; every service the
// connectors reach issues longer tokens.
const MinToken = 16

// form is one spelling of the token. Where fold is set, that byte is compared without regard to
// ASCII case (pat holds it lower-case): every byte of a hex form, and the two digits of each escape
// in a URL-escaped form, whose other bytes are the token's own and compared exactly. Case is decided
// per position of each candidate match, so text around a match cannot change how it is read.
type form struct {
	pat  []byte
	fold []bool
}

// tokenForms are the spellings of a token the host refuses in plugin output: the raw bytes, base64
// (standard and URL alphabets, padded or not, at each of the three alignments the token can take
// inside a longer encoded text), URL escaping (query, path and every byte escaped), and hex.
type tokenForms []form

func newTokenForms(token []byte) tokenForms {
	var f tokenForms
	add := func(p string, fold func(i int) bool) {
		if p == "" {
			return
		}
		fm := form{pat: []byte(p), fold: make([]bool, len(p))}
		for i := range fm.pat {
			if fm.fold[i] = fold(i); fm.fold[i] {
				fm.pat[i] = lowerASCII(fm.pat[i])
			}
		}
		for _, q := range f {
			if bytes.Equal(q.pat, fm.pat) && slices.Equal(q.fold, fm.fold) {
				return
			}
		}
		f = append(f, fm)
	}
	none := func(int) bool { return false }
	add(string(token), none)
	for k := 0; k < 3; k++ {
		// Inside a longer text the token starts k bytes into a 3-byte group; the characters that
		// encode only token bytes are the same whatever surrounds it, padded or not.
		enc := base64.StdEncoding.EncodeToString(append(make([]byte, k), token...))
		first, last := (k+2)/3*4, (k+len(token))/3*4
		if first < last {
			mid := enc[first:last]
			add(mid, none)
			add(strings.NewReplacer("+", "-", "/", "_").Replace(mid), none)
		}
	}
	for _, esc := range []string{url.QueryEscape(string(token)), url.PathEscape(string(token))} {
		digits := make([]bool, len(esc))
		for i := 0; i < len(esc); i++ {
			if esc[i] == '%' && i+2 < len(esc) {
				digits[i+1], digits[i+2] = true, true
				i += 2
			}
		}
		add(esc, func(i int) bool { return digits[i] })
	}
	var all strings.Builder
	for _, b := range token {
		fmt.Fprintf(&all, "%%%02x", b)
	}
	every := func(int) bool { return true }
	add(all.String(), every)
	add(hex.EncodeToString(token), every)
	return f
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// at reports whether b, from its start, matches the first n bytes of the form.
func (fm form) at(b []byte, n int) bool {
	for j := 0; j < n; j++ {
		c := b[j]
		if fm.fold[j] {
			c = lowerASCII(c)
		}
		if c != fm.pat[j] {
			return false
		}
	}
	return true
}

func (fm form) in(b []byte) bool {
	for i := 0; i+len(fm.pat) <= len(b); i++ {
		if fm.at(b[i:], len(fm.pat)) {
			return true
		}
	}
	return false
}

func (f tokenForms) found(b []byte) bool {
	for _, fm := range f {
		if fm.in(b) {
			return true
		}
	}
	return false
}

// ErrLineTooLong ends a stream whose plugin wrote a line longer than the gateway reads.
var ErrLineTooLong = errors.New("plugin output line over 16 MiB; stream ended")

// ErrBadFrame ends a stream whose plugin wrote a JSON line the gateway refuses too: a repeated
// object key (the scrub and the gateway could read different values) or nesting over MaxJSONDepth.
var ErrBadFrame = errors.New("plugin output line is a JSON frame the gateway refuses; stream ended")

// maxLine is the longest output line passed on: the gateway's own bound on a line.
const maxLine = 16 << 20

// scrubCopy copies plugin output to dst a whole line at a time, refusing it at the first line that
// carries the token. The gateway passes only whole lines, so a line is held until its end arrives:
// a token split over any number of writes is checked whole, and nothing of a refused line passes.
// A line is checked as written (every form) and, when it is JSON, every key and string in it,
// decoded, duplicates included (and a string that is itself JSON, a few levels deep), so JSON
// escaping such as \u0026 or \/ hides nothing. A JSON line with a repeated key is refused outright.
func scrubCopy(dst io.Writer, src io.Reader, f tokenForms) error {
	r := bufio.NewReaderSize(src, chunk)
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > maxLine {
			return ErrLineTooLong
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if len(line) > 0 && (err == nil || err == io.EOF) {
			if valid, refuse := JSONStrings(line, func(string) {}); valid && refuse != nil {
				return fmt.Errorf("%w: %v", ErrBadFrame, refuse)
			}
			if f.carried(line, 0) {
				return ErrTokenInOutput
			}
			if _, werr := dst.Write(line); werr != nil {
				return werr
			}
			line = line[:0]
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// carried reports whether b carries the token: in any form as written, or in any key or string of
// b read as JSON (every one, duplicates included), depth levels of JSON-in-a-string deep at most.
func (f tokenForms) carried(b []byte, depth int) bool {
	if f.found(b) {
		return true
	}
	if depth > 3 {
		return false
	}
	hit := false
	_, refuse := JSONStrings(b, func(s string) {
		if !hit && f.carried([]byte(s), depth+1) {
			hit = true
		}
	})
	// A string holding JSON nested too deep to walk is refused as if it carried the token.
	return hit || refuse == ErrTooDeep
}

// snapshotToken copies the service token into a file of its own for one stream, in dir (the
// host's staging directory), and returns that file and the token. The plugin is given the copy
// (--token-file) and the host scrubs for the same bytes, so a Secret rotated while the stream is
// open changes nothing for it; the next stream takes the new token. The sandbox hides the mounted
// token's directory from the plugin, so the copy is the only token it can read.
func snapshotToken(dir, path string) (string, []byte, error) {
	tok, err := readToken(path)
	if err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(dir, "token-")
	if err != nil {
		return "", nil, err
	}
	_, werr := f.Write(append(append([]byte{}, tok...), '\n'))
	cerr := f.Close()
	if werr != nil || cerr != nil || os.Chmod(f.Name(), 0o400) != nil {
		os.Remove(f.Name())
		return "", nil, errors.New("the service token could not be copied for the stream; refused")
	}
	return f.Name(), tok, nil
}

// readToken reads the service token the plugin is given (the hello's tokenPath), as connectors do:
// trimmed. A token the host cannot read is refused: the plugin, as the same user, could not either.
func readToken(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 {
		return nil, errors.New("the service token cannot be read; refused")
	}
	t := bytes.TrimSpace(b)
	if len(t) < MinToken {
		return nil, fmt.Errorf("the service token is shorter than %d bytes, too short to keep out of plugin output; refused", MinToken)
	}
	return t, nil
}
