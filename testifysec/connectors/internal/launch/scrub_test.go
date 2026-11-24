//go:build unix

package launch

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const scrubCanary = "conngw-test-token-7613470213-AbCdEf"

// chunked hands out its parts one Read at a time, as a plugin's separate writes arrive.
type chunked struct{ parts []string }

func (c *chunked) Read(p []byte) (int, error) {
	if len(c.parts) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.parts[0])
	if n < len(c.parts[0]) {
		c.parts[0] = c.parts[0][n:]
	} else {
		c.parts = c.parts[1:]
	}
	return n, nil
}

// recorder keeps each write separately, so a test can see what passed before a refusal.
type recorder struct{ writes []string }

func (r *recorder) Write(p []byte) (int, error) {
	r.writes = append(r.writes, string(p))
	return len(p), nil
}
func (r *recorder) all() string { return strings.Join(r.writes, "") }

// Every spelling the host refuses is caught, embedded in other text: raw, base64 in both alphabets
// at all three alignments and with or without padding, hex in either case, and URL escaping.
func TestEveryFormOfTheTokenIsRefused(t *testing.T) {
	f := newTokenForms([]byte(scrubCanary))
	forms := map[string]string{"raw": scrubCanary, "hex lower": hex.EncodeToString([]byte(scrubCanary)),
		"hex upper": strings.ToUpper(hex.EncodeToString([]byte(scrubCanary))),
		"query":     url.QueryEscape("a b " + scrubCanary), "path": url.PathEscape("a b " + scrubCanary)}
	var every strings.Builder
	for _, b := range []byte(scrubCanary) {
		every.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{b})))
	}
	forms["every byte escaped"] = every.String()
	for k, prefix := range []string{"", "B", "Be", "Bearer "} {
		in := []byte(prefix + scrubCanary + " tail")
		forms["std "+string(rune('0'+k))] = base64.StdEncoding.EncodeToString(in)
		forms["std raw "+string(rune('0'+k))] = base64.RawStdEncoding.EncodeToString(in)
		forms["url "+string(rune('0'+k))] = base64.URLEncoding.EncodeToString(in)
		forms["url raw "+string(rune('0'+k))] = base64.RawURLEncoding.EncodeToString(in)
	}
	for name, form := range forms {
		var out recorder
		err := scrubCopy(&out, strings.NewReader(`{"text":"`+form+`"}`+"\n"), f)
		if err != ErrTokenInOutput || out.all() != "" {
			t.Errorf("%s (%s): %v, passed %q", name, form, err, out.all())
		}
	}
}

// A token split over two writes is caught before any of it passes: at every split point nothing of
// the line that carries it reaches the caller.
func TestATokenSplitAcrossWritesIsRefused(t *testing.T) {
	f := newTokenForms([]byte(scrubCanary))
	b64 := base64.StdEncoding.EncodeToString([]byte("Bearer " + scrubCanary))
	for _, whole := range []string{scrubCanary, b64, strings.ToUpper(hex.EncodeToString([]byte(scrubCanary)))} {
		for i := 1; i < len(whole); i++ {
			var out recorder
			src := &chunked{parts: []string{`{"id":1,"text":"` + whole[:i], whole[i:] + `"}` + "\n"}}
			if err := scrubCopy(&out, src, f); err != ErrTokenInOutput {
				t.Fatalf("split %d of %q: %v", i, whole, err)
			}
			if got := out.all(); got != "" {
				t.Fatalf("split %d of %q: passed %q before the refusal", i, whole, got)
			}
		}
	}
}

// Clean output passes byte for byte, and a complete line is never held back waiting for more: each
// answer reaches the caller as soon as its line ends.
func TestCleanOutputPassesAtOnce(t *testing.T) {
	f := newTokenForms([]byte(scrubCanary))
	lines := []string{`{"id":1,"result":{}}` + "\n", `{"id":2,"text":"conngw-test"}` + "\n", "conn\n", strings.Repeat("x", 3*chunk) + "\n"}
	var out recorder
	if err := scrubCopy(&out, &chunked{parts: append([]string{}, lines...)}, f); err != nil {
		t.Fatal(err)
	}
	if out.all() != strings.Join(lines, "") {
		t.Fatalf("output changed: %q", out.all())
	}
	for i, w := range out.writes[:3] {
		if w != lines[i] {
			t.Fatalf("write %d %q, want the whole line %q", i, w, lines[i])
		}
	}
	// A line that arrives in parts passes once, whole, when its end arrives.
	out = recorder{}
	if err := scrubCopy(&out, &chunked{parts: []string{"a conngw-test-tok", "en is not it\n"}}, f); err != nil || len(out.writes) != 1 || out.all() != "a conngw-test-token is not it\n" {
		t.Fatalf("%v %q", err, out.writes)
	}
}

// URL escapes are refused whatever the case of their hex digits, for a token with reserved
// characters, also when an escape is cut between two writes.
func TestURLEscapesMatchInEitherCase(t *testing.T) {
	tok := "abcd/EFGH/ijkl+mnop=0123"
	f := newTokenForms([]byte(tok))
	for _, form := range []string{url.PathEscape(tok), url.QueryEscape(tok), "abcd%2fEFGH%2fijkl%2bmnop%3d0123",
		"abcd%2FEFGH%2fijkl%2Bmnop%3D0123"} {
		if !strings.Contains(form, "%") {
			continue
		}
		var out recorder
		if err := scrubCopy(&out, strings.NewReader("x="+form+"\n"), f); err != ErrTokenInOutput || out.all() != "" {
			t.Errorf("%q: %v, passed %q", form, err, out.all())
		}
		for i := 1; i < len(form); i++ {
			out = recorder{}
			if err := scrubCopy(&out, &chunked{parts: []string{"x=" + form[:i], form[i:] + "\n"}}, f); err != ErrTokenInOutput || !strings.HasPrefix("x=", out.all()) {
				t.Fatalf("%q split %d: %v, passed %q", form, i, err, out.all())
			}
		}
	}
}

// Text around an escaped token cannot change how its escapes are read: a '%' just before it (which
// would swallow the token's first two characters if the output were normalized as a whole) leaves
// the match intact, also split at every point.
func TestAPercentBeforeTheTokenDoesNotHideIt(t *testing.T) {
	tok := "ABCD/012345678901"
	f := newTokenForms([]byte(tok))
	for _, form := range []string{"%ABCD%2F012345678901", "%ABCD%2f012345678901", "%%ABCD%2F012345678901"} {
		var out recorder
		if err := scrubCopy(&out, strings.NewReader(form+"\n"), f); err != ErrTokenInOutput {
			t.Errorf("%q: %v, passed %q", form, err, out.all())
		}
		for i := 1; i < len(form); i++ {
			out = recorder{}
			if err := scrubCopy(&out, &chunked{parts: []string{form[:i], form[i:] + "\n"}}, f); err != ErrTokenInOutput || strings.Contains(out.all(), "ABCD") {
				t.Fatalf("%q split %d: %v, passed %q", form, i, err, out.all())
			}
		}
	}
}

// JSON escaping hides nothing: a line is also read as JSON and every string in it decoded, so
// json.Marshal's \u0026, \u003c and \u003e, a hand-written \u0061 or \/, and JSON inside a JSON
// string are all caught, whole and split at every point.
func TestJSONEscapingDoesNotHideTheToken(t *testing.T) {
	tok := "abcdefghijkl&mnop<qr>/st"
	f := newTokenForms([]byte(tok))
	marshalled, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]string{"type": "text", "text": "x " + tok}}}})
	inner, _ := json.Marshal(map[string]string{"text": string(marshalled)})
	for _, line := range []string{
		string(marshalled),
		string(inner),
		`{"text":"\u0061bcdefghijkl\u0026mnop\u003cqr\u003e\/st"}`,
		`{"k\u0061bcdefghijkl\u0026mnop\u003cqr\u003e\/st":1}`,
	} {
		if !strings.Contains(line, `\u`) {
			t.Fatalf("not escaped: %s", line)
		}
		for i := 0; i < len(line); i++ {
			var out recorder
			parts := []string{line + "\n"}
			if i > 0 {
				parts = []string{line[:i], line[i:] + "\n"}
			}
			if err := scrubCopy(&out, &chunked{parts: parts}, f); err != ErrTokenInOutput || out.all() != "" {
				t.Fatalf("%s split %d: %v, passed %q", line, i, err, out.all())
			}
		}
	}
}

// Short credentials keep every form: the host refuses a token under MinToken bytes rather than
// match only some of its encodings (a 6-byte token's base64 is 8 characters).
func TestAShortTokenIsRefused(t *testing.T) {
	p := t.TempDir() + "/t"
	if err := writeTestFile(p, "secret\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(p); err == nil {
		t.Fatal("a 6-byte token was accepted")
	}
	if err := writeTestFile(p, strings.Repeat("s", MinToken)); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(p); err != nil {
		t.Fatal(err)
	}
	// And at MinToken every form is kept, the shortest base64 run included.
	f := newTokenForms([]byte("abcdefghijklmnop"))
	for _, k := range []string{"", "B", "Be"} {
		in := base64.RawStdEncoding.EncodeToString([]byte(k + "abcdefghijklmnop"))
		if err := scrubCopy(io.Discard, strings.NewReader(in), f); err != ErrTokenInOutput {
			t.Errorf("alignment %d: %v", len(k), err)
		}
	}
}

// The host refuses a token file it cannot read, or one that is empty.
func TestAnUnreadableTokenIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, content := range []string{"", " \n"} {
		p := dir + "/t"
		if err := writeTestFile(p, content); err != nil {
			t.Fatal(err)
		}
		if _, err := readToken(p); err == nil {
			t.Errorf("%q: accepted", content)
		}
	}
	if _, err := readToken(dir + "/missing"); err == nil {
		t.Error("missing: accepted")
	}
	if err := writeTestFile(dir+"/ok", " "+scrubCanary+"\n"); err != nil {
		t.Fatal(err)
	}
	if tok, err := readToken(dir + "/ok"); err != nil || !bytes.Equal(tok, []byte(scrubCanary)) {
		t.Fatalf("%q %v", tok, err)
	}
}

func writeTestFile(p, content string) error { return os.WriteFile(p, []byte(content), 0o600) }

// A JSON line with a repeated key, at any depth, is refused outright: the scrub and the gateway
// could read different values from it ("text": token then "text": null keeps the token in a
// decoder that skips nulls). A repeated key inside a string that is itself JSON is walked key by
// key, so the token there is caught too.
func TestARepeatedKeyIsRefused(t *testing.T) {
	tok := "abcdefghijklmnop/qrst"
	f := newTokenForms([]byte(tok))
	esc := `abcdefghijklmnop\/qrst`
	for _, line := range []string{
		`{"text":"` + esc + `","text":null}`,
		`{"a":{"b":1,"b":2}}`,
		`{"a":[{"x":1},{"y":1,"y":"z"}]}`,
		`{"id":1,"id":1}`,
	} {
		var out recorder
		if err := scrubCopy(&out, strings.NewReader(line+"\n"), f); !errors.Is(err, ErrBadFrame) || out.all() != "" {
			t.Errorf("%s: %v, passed %q", line, err, out.all())
		}
	}
	inner, _ := json.Marshal(map[string]string{"text": `{"token":"` + esc + `","token":"safe"}`})
	var out recorder
	if err := scrubCopy(&out, strings.NewReader(string(inner)+"\n"), f); err != ErrTokenInOutput {
		t.Errorf("JSON in a string with a repeated key: %v, passed %q", err, out.all())
	}
	// Distinct keys in sibling objects are not repeats.
	if valid, refuse := JSONStrings([]byte(`{"a":{"k":1},"b":{"k":2},"c":[{"k":3},{"k":4}]}`), func(string) {}); !valid || refuse != nil {
		t.Fatalf("siblings: %v %v", valid, refuse)
	}
	// A repeated key does not stop the walk: a token after it inside a JSON string is still seen.
	after, _ := json.Marshal(map[string]string{"text": `{"x":1,"x":2,"t":"` + esc + `"}`})
	if err := scrubCopy(&out, strings.NewReader(string(after)+"\n"), f); err != ErrTokenInOutput {
		t.Errorf("token after a repeated key in a JSON string: %v", err)
	}
}

// Nesting is bounded: a line of millions of '[' is refused once it passes MaxJSONDepth levels,
// before more levels are allocated, and quickly; at the bound it is accepted.
func TestDeepNestingIsRefused(t *testing.T) {
	f := newTokenForms([]byte(scrubCanary))
	deep := strings.Repeat("[", 4<<20) + strings.Repeat("]", 4<<20)
	start := time.Now()
	var out recorder
	if err := scrubCopy(&out, strings.NewReader(deep+"\n"), f); !errors.Is(err, ErrBadFrame) || out.all() != "" {
		t.Fatalf("deep nesting: %v, passed %d bytes", err, len(out.all()))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("deep nesting took %v", d)
	}
	ok := strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth)
	if valid, refuse := JSONStrings([]byte(ok), func(string) {}); !valid || refuse != nil {
		t.Fatalf("at the bound: %v %v", valid, refuse)
	}
	inText, _ := json.Marshal(map[string]string{"text": strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1)})
	if err := scrubCopy(&out, strings.NewReader(string(inText)+"\n"), f); err == nil {
		t.Fatal("JSON nested too deep inside a string passed")
	}
}
