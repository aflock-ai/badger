package main

// Conversion between Confluence storage format (XHTML with ac:/ri: elements) and markdown.
// Best effort and bounded: the page body is hostile input, so depth, table size and output are
// capped and anything unknown is named rather than expanded.

import (
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxDepth   = 48        // deeper elements are flattened into their ancestor
	maxRows    = 100       // table rows kept
	maxCols    = 20        // table columns kept
	maxCell    = 300       // bytes per table cell
	maxConvert = 256 << 10 // converter output; the server caps again at 48 KiB
)

type node struct {
	name string // "" for text; prefixed name otherwise, e.g. "ac:structured-macro"
	attr map[string]string
	text string
	kids []*node
}

func parseStorage(s string) (*node, bool) {
	d := xml.NewDecoder(strings.NewReader("<r>" + s + "</r>"))
	// Not xml.HTMLAutoClose: it matches local names only and would self-close ac:link.
	d.Strict, d.AutoClose, d.Entity = false, []string{"br", "hr", "img", "col", "wbr"}, xml.HTMLEntity
	root := &node{name: "r"}
	stack := []*node{root}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return root, true
		}
		if err != nil {
			return root, false
		}
		top := stack[len(stack)-1]
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) > maxDepth {
				// Flatten into one fixed node under the element at the depth limit: keep the
				// text, drop the structure, so the tree never grows deeper than maxDepth+1.
				// A rich-text body renders wherever it lands, including inside a macro.
				anchor := stack[maxDepth]
				if len(anchor.kids) == 0 || anchor.kids[len(anchor.kids)-1].name != "ac:rich-text-body" {
					anchor.kids = append(anchor.kids, &node{name: "ac:rich-text-body"})
				}
				stack = append(stack, anchor.kids[len(anchor.kids)-1])
				continue
			}
			n := &node{name: qname(t.Name), attr: map[string]string{}}
			for _, a := range t.Attr {
				n.attr[qname(a.Name)] = a.Value
			}
			top.kids = append(top.kids, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			top.kids = append(top.kids, &node{text: string(t)})
		}
	}
}

func qname(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

// storageToMarkdown converts a storage-format body. The note is set when the body was malformed
// or the output hit the converter cap.
func storageToMarkdown(s string) string {
	out, truncated, ok := convert(s)
	if truncated {
		out += "\n[page body truncated by the converter]"
	}
	if !ok {
		out += "\n[the page body was not well-formed; conversion is partial]"
	}
	return out
}

// convert returns the markdown without notes, whether it was cut at maxConvert, and whether the
// body parsed cleanly.
func convert(s string) (out string, truncated, ok bool) {
	root, ok := parseStorage(s)
	var r renderer
	r.blocks(root.kids)
	out = strings.TrimSpace(r.b.String())
	if len(out) > maxConvert {
		return cut(out, maxConvert), true, ok
	}
	return out, false, ok
}

type renderer struct{ b strings.Builder }

func (r *renderer) para(s string) {
	if s = strings.TrimSpace(s); s != "" && r.b.Len() <= maxConvert {
		r.b.WriteString(s + "\n\n")
	}
}

var blockNames = map[string]bool{"r": true, "p": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"ul": true, "ol": true, "table": true, "pre": true, "blockquote": true, "hr": true, "div": true, "section": true,
	"ac:structured-macro": true, "ac:macro": true, "ac:layout": true, "ac:layout-section": true, "ac:layout-cell": true,
	"ac:task-list": true, "ac:rich-text-body": true}

// blocks renders a mixed list: runs of inline nodes become paragraphs.
func (r *renderer) blocks(kids []*node) {
	var run strings.Builder
	for _, k := range kids {
		if !blockNames[k.name] {
			run.WriteString(inline(k))
			continue
		}
		r.para(run.String())
		run.Reset()
		r.block(k)
	}
	r.para(run.String())
}

func (r *renderer) block(n *node) {
	switch n.name {
	case "h1", "h2", "h3", "h4", "h5", "h6":
		r.para(strings.Repeat("#", int(n.name[1]-'0')) + " " + oneLine(inlineKids(n)))
	case "p":
		r.blocks(n.kids)
	case "hr":
		r.para("---")
	case "pre":
		r.para(fence("", textOf(n)))
	case "ul", "ol":
		i := 0
		for _, li := range n.kids {
			if li.name != "li" {
				continue
			}
			i++
			mark := "- "
			if n.name == "ol" {
				mark = strconv.Itoa(i) + ". "
			}
			r.b.WriteString(prefix(sub(li.kids), mark, strings.Repeat(" ", len(mark))))
		}
		r.b.WriteString("\n")
	case "blockquote":
		r.para(prefix(sub(n.kids), "> ", "> "))
	case "table":
		r.para(table(n))
	case "ac:task-list":
		for _, t := range n.kids {
			if t.name == "ac:task" {
				box := "[ ]"
				if strings.TrimSpace(textOf(child(t, "ac:task-status"))) == "complete" {
					box = "[x]"
				}
				r.b.WriteString("- " + box + " " + oneLine(sub(kidsOf(child(t, "ac:task-body")))) + "\n")
			}
		}
		r.b.WriteString("\n")
	case "ac:structured-macro", "ac:macro":
		r.macro(n)
	default:
		r.blocks(n.kids)
	}
}

func (r *renderer) macro(n *node) {
	name := n.attr["ac:name"]
	params := map[string]string{}
	for _, k := range n.kids {
		if k.name == "ac:parameter" {
			params[k.attr["ac:name"]] = textOf(k)
		}
	}
	body := child(n, "ac:rich-text-body")
	switch {
	case name == "code" || name == "noformat":
		r.para(fence(params["language"], textOf(child(n, "ac:plain-text-body"))))
	case body != nil && (name == "section" || name == "column" || name == "excerpt" || name == "details"):
		r.blocks(body.kids)
	case body != nil:
		head := "> **" + name + "**"
		if t := oneLine(params["title"]); t != "" {
			head += ": " + t
		}
		r.para(head + "\n" + prefix(sub(body.kids), "> ", "> "))
	default:
		r.para(inline(n))
	}
}

// sub renders nodes as blocks into a fresh buffer.
func sub(kids []*node) string {
	var r renderer
	r.blocks(kids)
	return strings.TrimSpace(r.b.String())
}

func prefix(s, first, rest string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		p := rest
		if i == 0 {
			p = first
		}
		lines[i] = strings.TrimRight(p+l, " ")
	}
	return strings.Join(lines, "\n") + "\n"
}

func table(n *node) string {
	var rows [][]string
	extra := 0
	var walk func(*node)
	walk = func(t *node) {
		for _, k := range t.kids {
			switch k.name {
			case "thead", "tbody", "tfoot":
				walk(k)
			case "tr":
				if len(rows) >= maxRows {
					extra++
					continue
				}
				var row []string
				for _, c := range k.kids {
					if (c.name == "td" || c.name == "th") && len(row) < maxCols {
						cell := strings.ReplaceAll(oneLine(sub(c.kids)), "|", `\|`)
						if len(cell) > maxCell {
							cell = cut(cell, maxCell) + "..."
						}
						row = append(row, cell)
					}
				}
				rows = append(rows, row)
			}
		}
	}
	walk(n)
	if len(rows) == 0 {
		return ""
	}
	cols := 0
	for _, r := range rows {
		cols = max(cols, len(r))
	}
	var b strings.Builder
	for i, r := range rows {
		for len(r) < cols {
			r = append(r, "")
		}
		b.WriteString("| " + strings.Join(r, " | ") + " |\n")
		if i == 0 {
			b.WriteString(strings.Repeat("| --- ", cols) + "|\n")
		}
	}
	if extra > 0 {
		fmt.Fprintf(&b, "[table truncated: %d more rows]\n", extra)
	}
	return b.String()
}

func inlineKids(n *node) string {
	var b strings.Builder
	for _, k := range n.kids {
		b.WriteString(inline(k))
	}
	return b.String()
}

func inline(n *node) string {
	switch n.name {
	case "":
		return collapse(n.text)
	case "br":
		return "\n"
	case "ac:emoticon", "ac:placeholder", "ac:parameter", "colgroup":
		return ""
	case "time":
		return n.attr["datetime"]
	case "ac:link":
		return link(n)
	case "ac:image":
		name := ""
		if a := child(n, "ri:attachment"); a != nil {
			name = a.attr["ri:filename"]
		} else if u := child(n, "ri:url"); u != nil {
			name = u.attr["ri:value"]
		}
		return "[image: " + name + "]"
	case "ac:structured-macro", "ac:macro":
		for _, k := range n.kids {
			if k.name == "ac:parameter" && k.attr["ac:name"] == "title" && n.attr["ac:name"] == "status" {
				return "[status: " + oneLine(textOf(k)) + "]"
			}
		}
		return "[macro " + n.attr["ac:name"] + ", not expanded]"
	}
	// Each subtree is rendered exactly once, so nesting costs linear work.
	in := inlineKids(n)
	wrap := func(m string) string {
		if t := strings.TrimSpace(in); t != "" {
			return m + t + m
		}
		return in
	}
	switch n.name {
	case "strong", "b":
		return wrap("**")
	case "em", "i":
		return wrap("*")
	case "s", "del":
		return wrap("~~")
	case "code":
		return "`" + strings.TrimSpace(in) + "`"
	case "a":
		if h := n.attr["href"]; safeURL.MatchString(h) {
			return "[" + strings.TrimSpace(in) + "](" + h + ")"
		}
	}
	return in
}

func link(n *node) string {
	text := strings.TrimSpace(textOf(child(n, "ac:plain-text-link-body")) + inlineKids(orEmpty(child(n, "ac:link-body"))))
	target := ""
	if p := child(n, "ri:page"); p != nil {
		target = fmt.Sprintf("page %q", p.attr["ri:content-title"])
	} else if a := child(n, "ri:attachment"); a != nil {
		target = fmt.Sprintf("attachment %q", a.attr["ri:filename"])
	} else if u := child(n, "ri:user"); u != nil {
		target = "@" + u.attr["ri:username"] + u.attr["ri:userkey"]
	}
	if text == "" {
		return target
	}
	return text + " (" + target + ")"
}

var safeURL = regexp.MustCompile(`^(https?://|mailto:|/)[^\s()]*$`)

func child(n *node, name string) *node {
	for _, k := range n.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

func orEmpty(n *node) *node {
	if n == nil {
		return &node{}
	}
	return n
}

func kidsOf(n *node) []*node { return orEmpty(n).kids }

func textOf(n *node) string {
	if n == nil {
		return ""
	}
	if n.name == "" {
		return n.text
	}
	var b strings.Builder
	for _, k := range n.kids {
		b.WriteString(textOf(k))
	}
	return b.String()
}

func oneLine(s string) string { return strings.TrimSpace(collapse(s)) }

// collapse turns each run of ASCII whitespace into one space.
func collapse(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	white := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\f' {
			if !white {
				b.WriteByte(' ')
			}
			white = true
			continue
		}
		white = false
		b.WriteByte(c)
	}
	return b.String()
}

func fence(lang, code string) string {
	run, longest := 0, 0 // one pass: the fence is one backtick longer than any run inside
	for i := 0; i < len(code); i++ {
		if code[i] == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	f := strings.Repeat("`", max(3, longest+1))
	return f + lang + "\n" + strings.Trim(code, "\n") + "\n" + f
}

func cut(s string, n int) string {
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:min(n, len(s))]
}

// markdownToStorage converts the small markdown subset a model writes: headings, paragraphs,
// bullet and numbered lists, fenced code (as the code macro), rules, and inline bold, code and
// http(s) links. Everything else is kept as escaped text.
func markdownToStorage(md string) string {
	var b, para strings.Builder
	list := ""
	flush := func() {
		if para.Len() > 0 {
			b.WriteString("<p>" + inlineMD(strings.TrimSpace(para.String())) + "</p>")
			para.Reset()
		}
		if list != "" {
			b.WriteString("</" + list + ">")
			list = ""
		}
	}
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "```"):
			flush()
			open := strings.TrimSpace(t)
			lang := strings.TrimSpace(strings.TrimLeft(open, "`"))
			fenceLen := len(open) - len(strings.TrimLeft(open, "`"))
			closes := func(l string) bool { // a run of at least fenceLen backticks and nothing else
				l = strings.TrimSpace(l)
				return len(l) >= fenceLen && strings.Trim(l, "`") == ""
			}
			var code []string
			for i++; i < len(lines) && !closes(lines[i]); i++ {
				code = append(code, lines[i])
			}
			b.WriteString(`<ac:structured-macro ac:name="code">`)
			if langRE.MatchString(lang) {
				b.WriteString(`<ac:parameter ac:name="language">` + lang + `</ac:parameter>`)
			}
			b.WriteString("<ac:plain-text-body><![CDATA[" + strings.ReplaceAll(clean(strings.Join(code, "\n")), "]]>", "]]]]><![CDATA[>") +
				"]]></ac:plain-text-body></ac:structured-macro>")
		case t == "":
			flush()
		case t == "---":
			flush()
			b.WriteString("<hr />")
		case heading.MatchString(t):
			flush()
			m := heading.FindStringSubmatch(t)
			n := strconv.Itoa(len(m[1]))
			b.WriteString("<h" + n + ">" + inlineMD(m[2]) + "</h" + n + ">")
		case bullet.MatchString(t) || numbered.MatchString(t):
			kind, re := "ul", bullet
			if numbered.MatchString(t) {
				kind, re = "ol", numbered
			}
			if list != kind {
				flush()
				b.WriteString("<" + kind + ">")
				list = kind
			}
			b.WriteString("<li>" + inlineMD(re.ReplaceAllString(t, "")) + "</li>")
		default:
			if list != "" {
				flush()
			}
			para.WriteString(t + " ")
		}
	}
	flush()
	return b.String()
}

var (
	heading  = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	bullet   = regexp.MustCompile(`^[-*]\s+`)
	numbered = regexp.MustCompile(`^\d{1,9}[.)]\s+`)
	langRE   = regexp.MustCompile(`^[a-z0-9+#-]{1,20}$`)
)

func inlineMD(s string) string {
	var b strings.Builder
	for s != "" {
		switch {
		case strings.HasPrefix(s, "`") && strings.Contains(s[1:], "`"):
			end := strings.Index(s[1:], "`") + 1
			b.WriteString("<code>" + esc(s[1:end]) + "</code>")
			s = s[end+1:]
		case strings.HasPrefix(s, "**") && strings.Contains(s[2:], "**"):
			end := strings.Index(s[2:], "**") + 2
			b.WriteString("<strong>" + inlineMD(s[2:end]) + "</strong>")
			s = s[end+2:]
		case s[0] == '[':
			// Linear: every character scanned for a link that fails is emitted as text and
			// never scanned again.
			n := mdLinkAt(s, &b)
			s = s[n:]
		default:
			_, n := utf8.DecodeRuneInString(s)
			b.WriteString(esc(s[:n]))
			s = s[n:]
		}
	}
	return b.String()
}

// mdLinkAt handles s starting with '[': it writes a [text](http(s)://url) link, or the
// characters it looked at as escaped text, and returns how many bytes it consumed.
func mdLinkAt(s string, b *strings.Builder) int {
	j := strings.IndexAny(s[1:], "[]") + 1
	if j == 0 || s[j] == '[' || j == 1 {
		n := max(j, 1)
		if j == 0 {
			n = len(s)
		}
		b.WriteString(esc(s[:n]))
		return n
	}
	rest := s[j+1:]
	if !strings.HasPrefix(rest, "(http://") && !strings.HasPrefix(rest, "(https://") {
		b.WriteString(esc(s[:j+1]))
		return j + 1
	}
	k := 1
	for k < len(rest) && rest[k] > ' ' && rest[k] != '(' && rest[k] != ')' {
		k++
	}
	scheme := len("(http://")
	if strings.HasPrefix(rest, "(https://") {
		scheme++
	}
	if k < len(rest) && rest[k] == ')' && k > scheme {
		b.WriteString(`<a href="` + esc(rest[1:k]) + `">` + esc(s[1:j]) + "</a>")
		return j + 1 + k + 1
	}
	b.WriteString(esc(s[:j+1+k]))
	return j + 1 + k
}

func esc(s string) string { return html.EscapeString(clean(s)) }

// clean drops control characters XML 1.0 cannot carry.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0xFFFE || r == 0xFFFF {
			return -1
		}
		return r
	}, s)
}
