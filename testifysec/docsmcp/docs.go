package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Bundle is what docs/tools/generate.ts --bundle prints: every page of one docs tree, rendered for
// one commit, and the configuration reference read from the Go source.
type Bundle struct {
	Schema int         `json:"schema"`
	Date   string      `json:"date"`
	Roots  []Root      `json:"roots"`
	Topics []Topic     `json:"topics"`
	Config []Component `json:"config"`
}

type Root struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Dirty   bool   `json:"dirty"`
}

type Topic struct {
	ID              string `json:"id"`
	Section         string `json:"section"`
	Title           string `json:"title"`
	Description     string `json:"description"`
	SidebarLabel    string `json:"sidebarLabel"`
	SidebarPosition int    `json:"sidebarPosition"`
	Body            string `json:"body"`
}

type Component struct {
	Component string  `json:"component"`
	Title     string  `json:"title"`
	Root      string  `json:"root"`
	Fields    []Field `json:"fields"`
}

type Field struct {
	Key      string `json:"key"`
	Type     string `json:"type"`
	Optional bool   `json:"optional"`
	Default  string `json:"default"`
	Doc      string `json:"doc"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Symbol   string `json:"symbol"`
}

// parseBundle refuses anything but a well-formed schema-1 bundle whose first root is badger.
func parseBundle(raw []byte) (*Bundle, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var b Bundle
	if err := d.Decode(&b); err != nil {
		return nil, fmt.Errorf("docs bundle: %w", err)
	}
	if b.Schema != 1 {
		return nil, fmt.Errorf("docs bundle: schema %d, want 1", b.Schema)
	}
	if len(b.Roots) == 0 || b.Roots[0].Name != "badger" || b.Roots[0].Commit == "" {
		return nil, errors.New("docs bundle: the first root must be badger, with a commit")
	}
	if len(b.Topics) == 0 {
		return nil, errors.New("docs bundle: no topics")
	}
	seen := map[string]bool{}
	for _, t := range b.Topics {
		if t.ID == "" || seen[t.ID] {
			return nil, fmt.Errorf("docs bundle: topic id %q is empty or repeated", t.ID)
		}
		seen[t.ID] = true
	}
	return &b, nil
}

// Overlay is a private docs tree loaded on top of the public one. Its topics are added under
// overlay/<name>/ and can never replace or hide a public topic.
type Overlay struct {
	Name   string
	Bundle *Bundle
}

var overlayName = regexp.MustCompile(`[^a-z0-9-]+`)

func loadOverlay(dir string) (Overlay, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return Overlay{}, fmt.Errorf("overlay %s: %w", dir, err)
	}
	b, err := parseBundle(raw)
	if err != nil {
		return Overlay{}, fmt.Errorf("overlay %s: %w", dir, err)
	}
	// The name comes from the directory itself, so "." and ".." name the directory they mean.
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Overlay{}, fmt.Errorf("overlay %s: %w", dir, err)
	}
	name := strings.Trim(overlayName.ReplaceAllString(strings.ToLower(filepath.Base(abs)), "-"), "-")
	if name == "" {
		return Overlay{}, fmt.Errorf("overlay %s: no usable name in the directory name", dir)
	}
	return Overlay{Name: name, Bundle: b}, nil
}

type Section struct {
	Slug, Title string
	Level       int
	Text        string // the heading line and everything up to the next heading of any level
}

var heading = regexp.MustCompile(`^(#{1,6}) +(.+?) *#*$`)

var fenceRun = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")

// sections splits a page at its headings, outside fenced code, with GitHub's anchor slugs.
func sections(body string) []Section {
	var out []Section
	used := map[string]bool{}
	// A fence (CommonMark) opens with three or more backticks or tildes, indented at most three
	// spaces, and closes only with a run of the same character at least as long and nothing after it.
	var fenceChar byte
	fenceLen := 0
	for _, line := range strings.SplitAfter(body, "\n") {
		if m := fenceRun.FindStringSubmatch(strings.TrimRight(line, "\n")); m != nil {
			rest := strings.TrimRight(line, "\n")[len(m[0]):]
			switch {
			case fenceLen == 0 && !(m[1][0] == '`' && strings.Contains(rest, "`")):
				fenceChar, fenceLen = m[1][0], len(m[1])
			case fenceLen > 0 && m[1][0] == fenceChar && len(m[1]) >= fenceLen && strings.TrimSpace(rest) == "":
				fenceLen = 0
			}
		}
		fence := fenceLen > 0
		if m := heading.FindStringSubmatch(strings.TrimRight(line, "\n")); m != nil && !fence {
			// A repeated slug takes the first free -N, checked against every slug already given, so
			// "Build", "Build-1", "Build" are build, build-1, build-2.
			base := slugify(m[2])
			slug := base
			for n := 1; used[slug]; n++ {
				slug = fmt.Sprintf("%s-%d", base, n)
			}
			used[slug] = true
			out = append(out, Section{Slug: slug, Title: m[2], Level: len(m[1])})
		}
		if len(out) > 0 {
			out[len(out)-1].Text += line
		}
	}
	return out
}

func slugify(title string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(title) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || ('a' <= r && r <= 'z') || ('0' <= r && r <= '9') || r > 127:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Docs answers the tools from the embedded bundle and any overlays. It reads nothing else.
type Docs struct {
	base     *Bundle
	overlays []Overlay
	topics   map[string]entry
	order    []string
}

type entry struct {
	topic   Topic
	overlay *Overlay
}

func newDocs(base *Bundle, overlays []Overlay) (*Docs, error) {
	d := &Docs{base: base, overlays: overlays, topics: map[string]entry{}}
	for _, t := range base.Topics {
		d.topics[t.ID] = entry{topic: t}
		d.order = append(d.order, t.ID)
	}
	for i := range overlays {
		o := &d.overlays[i]
		for _, t := range o.Bundle.Topics {
			id := "overlay/" + o.Name + "/" + t.ID
			if _, ok := d.topics[id]; ok {
				return nil, fmt.Errorf("overlay %s: topic %s is loaded twice", o.Name, id)
			}
			t.ID = id
			d.topics[id] = entry{topic: t, overlay: o}
			d.order = append(d.order, id)
		}
	}
	return d, nil
}

func short(r Root) string {
	s := r.Commit
	if len(s) > 12 {
		s = s[:12]
	}
	if r.Dirty {
		s += "+dirty"
	}
	return s
}

func (d *Docs) stamp() string {
	r := d.base.Roots[0]
	return fmt.Sprintf("badger %s at %s (%s)", r.Version, short(r), d.base.Date)
}

// header is the first line of every answer, so an agent always sees which build it describes; an
// overlay built against another badger commit says so on every read.
func (d *Docs) header(e entry) string {
	h := d.stamp()
	if e.overlay != nil {
		ob := e.overlay.Bundle.Roots[0]
		h += fmt.Sprintf("; overlay %s", e.overlay.Name)
		if ob.Commit != d.base.Roots[0].Commit {
			h += fmt.Sprintf(", built against badger %s at %s, not this build", ob.Version, short(ob))
		}
	}
	return h
}

func (d *Docs) lookup(name string) (entry, string, bool) {
	id, frag, _ := strings.Cut(strings.TrimSpace(name), "#")
	id = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(id, "./"), "docs/"), ".md")
	e, ok := d.topics[id]
	return e, frag, ok
}

func (d *Docs) listTopics(section string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: topics (read one with read, a section with read topic#section)\n", d.stamp())
	for _, id := range d.order {
		t := d.topics[id].topic
		if section != "" && t.Section != section && !strings.HasPrefix(id, section+"/") {
			continue
		}
		fmt.Fprintf(&b, "- %s (%s): %s\n", id, t.Title, t.Description)
	}
	return b.String()
}

func (d *Docs) read(name string) (string, bool) {
	e, frag, ok := d.lookup(name)
	if !ok {
		return fmt.Sprintf("no topic %q. Topics:\n%s", name, d.listTopics("")), true
	}
	text := e.topic.Body
	if frag != "" {
		text = ""
		var slugs []string
		for _, s := range sections(e.topic.Body) {
			slugs = append(slugs, s.Slug)
			if s.Slug == frag {
				text = s.Text
			}
		}
		if text == "" {
			return fmt.Sprintf("no section %q in %s. Sections: %s", frag, e.topic.ID, strings.Join(slugs, ", ")), true
		}
	}
	return d.header(e) + "\n\n" + strings.TrimSpace(text) + "\n", false
}

type hit struct {
	score int
	line  string
}

func terms(query string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(query), func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || ('a' <= r && r <= 'z') || ('0' <= r && r <= '9'))
	}) {
		if len(w) > 1 {
			out = append(out, w)
		}
	}
	return out
}

// score ranks by how many distinct terms match first, then by where: a title or key counts five
// times a body or comment.
func score(ts []string, title, body string) int {
	title, body = strings.ToLower(title), strings.ToLower(body)
	matched, s := 0, 0
	for _, t := range ts {
		n := 5*strings.Count(title, t) + strings.Count(body, t)
		if n > 0 {
			matched++
			s += n
		}
	}
	if matched == 0 {
		return 0
	}
	return matched*1000 + s
}

// snippet is about 180 bytes of text around the first term found, cut on rune boundaries. Offsets
// come from a case-insensitive match on the text itself, never from a lowercased copy, whose byte
// length can differ.
func snippet(text string, ts []string) string {
	flat := strings.Join(strings.Fields(text), " ")
	at := -1
	for _, t := range ts {
		if loc := regexp.MustCompile("(?i)" + regexp.QuoteMeta(t)).FindStringIndex(flat); loc != nil && (at < 0 || loc[0] < at) {
			at = loc[0]
		}
	}
	start := max(at-60, 0)
	end := min(start+180, len(flat))
	for start > 0 && !utf8.RuneStart(flat[start]) {
		start--
	}
	for end < len(flat) && !utf8.RuneStart(flat[end]) {
		end++
	}
	return strings.TrimSpace(flat[start:end])
}

func (d *Docs) search(query string) (string, bool) {
	ts := terms(query)
	if len(ts) == 0 {
		return "search needs a query of at least one word", true
	}
	var hits []hit
	for _, id := range d.order {
		t := d.topics[id].topic
		for _, s := range sections(t.Body) {
			if n := score(ts, s.Title+" "+t.Title, s.Text); n > 0 {
				hits = append(hits, hit{n, fmt.Sprintf("- %s#%s (%s > %s): %s", id, s.Slug, t.Title, s.Title, snippet(s.Text, ts))})
			}
		}
	}
	for _, c := range d.base.Config {
		for _, f := range c.Fields {
			if n := score(ts, c.Component+" "+f.Key, f.Doc+" "+f.Type); n > 0 {
				def := ""
				if f.Default != "" {
					def = ", default " + f.Default
				}
				hits = append(hits, hit{n, fmt.Sprintf("- config %s %s (%s%s): %s [get_config_reference %s]", c.Component, f.Key, f.Type, def, f.Doc, c.Component)})
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	if len(hits) > 12 {
		hits = hits[:12]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d results for %q\n", d.stamp(), len(hits), query)
	for _, h := range hits {
		b.WriteString(h.line + "\n")
	}
	return b.String(), false
}

func (d *Docs) configReference(component string) (string, bool) {
	var names []string
	for _, c := range d.base.Config {
		names = append(names, c.Component)
		if c.Component != component {
			continue
		}
		r := d.base.Roots[0]
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %s, every key the component decodes, read from its Go source at commit %s.\n", d.stamp(), c.Title, r.Commit)
		b.WriteString("A default is listed only where the source comment states one; otherwise read the cited line.\n\n")
		for _, f := range c.Fields {
			fmt.Fprintf(&b, "- `%s` `%s`", f.Key, f.Type)
			if f.Optional {
				b.WriteString(" optional")
			}
			if f.Default != "" {
				fmt.Fprintf(&b, ", default `%s`", f.Default)
			}
			fmt.Fprintf(&b, ". %s:%d (%s @ %s)", f.File, f.Line, f.Symbol, short(r))
			if f.Doc != "" {
				b.WriteString(". " + f.Doc)
			}
			b.WriteString("\n")
		}
		return b.String(), false
	}
	return fmt.Sprintf("no component %q; components: %s", component, strings.Join(names, ", ")), true
}

func (d *Docs) version() string {
	type ov struct {
		Name    string `json:"name"`
		Roots   []Root `json:"roots"`
		Matches bool   `json:"matchesBadger"`
	}
	v := struct {
		Badger   Root   `json:"badger"`
		Date     string `json:"date"`
		Build    any    `json:"build"`
		Overlays []ov   `json:"overlays"`
	}{Badger: d.base.Roots[0], Date: d.base.Date, Build: buildStamp(), Overlays: []ov{}}
	for _, o := range d.overlays {
		v.Overlays = append(v.Overlays, ov{o.Name, o.Bundle.Roots, o.Bundle.Roots[0].Commit == d.base.Roots[0].Commit})
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}

func (d *Docs) call(tool string, raw json.RawMessage) (string, bool) {
	var a struct {
		Section   string `json:"section"`
		Query     string `json:"query"`
		Topic     string `json:"topic"`
		Component string `json:"component"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return "arguments must be a JSON object", true
		}
	}
	switch tool {
	case "list_topics":
		return d.listTopics(a.Section), false
	case "search":
		return d.search(a.Query)
	case "read":
		return d.read(a.Topic)
	case "get_config_reference":
		return d.configReference(a.Component)
	case "version":
		return d.version(), false
	}
	return fmt.Sprintf("unknown tool %q", tool), true
}
