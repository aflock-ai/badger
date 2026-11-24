package marking

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// A Scheme is a classification scheme loaded from data: an ordered list of levels and the groups
// a banner may carry after its level. The kinds of group are code (require, release, sourced); every
// parameter of them is data. The built-in schemes are presets (schemes/*.json); a deployment may
// supply its own file. A scheme is validated in full when it loads and never changes after: its
// fields are for reading, and Configure keeps a copy of its own.
type Scheme struct {
	Name    string
	Version int
	Levels  []Level
	Groups  []Group
	Retired []Retired
	digest  string
	rules   *Scheme // the deep copy every engine method uses (engine.go, r)
}

// Level is one classification level. Its place in Scheme.Levels is its order: there is no rank
// field that could contradict the list.
type Level struct {
	Name string
}

// Group is one part of a banner after the level.
type Group struct {
	Name     string
	Kind     string // "require", "release" or "sourced"
	Position int    // canonical banner order
	First    bool   // must be the first group after the level
	Levels   []int  // levels the group may appear at; empty is every level
	// AbsorbedFrom is the level from which a holder need not carry the group; -1 is never.
	AbsorbedFrom int
	Prefix       string // an opaque identifier group (each token is Prefix + an identifier)
	// SpecifiedPrefix marks a token's specified variant in a banner (a "specified" token needs it,
	// a "basic" one refuses it, an "either" one takes both).
	SpecifiedPrefix string
	Tokens          []Token // in canonical order
	// Release parameters (Kind "release").
	Home           string
	NoRelease      string // the require token meaning "home only"
	RestrictedFrom int    // from this level, content without a release line is home-only; -1 never
	ReleaseLine    string
	DisplayLine    string
	InGroup        string // the group whose banner group also holds the release lines
	noReleaseIn    string // the require group that owns NoRelease, found by its portion at load
	Countries      []string
	Tetragraphs    map[string][]string
}

// Token is one word a group accepts.
type Token struct {
	Token   string
	Portion string
	Levels  []int  // empty: the group's levels
	Variant string // "", "basic", "specified" or "either"
	Suffix  bool   // the token may carry an opaque "-X" sub-compartment
}

// Retired is a marking that is refused with a message instead of parsed.
type Retired struct {
	Token   string
	Message string
}

// Digest is "sha256:<hex>" over the scheme's canonical form (canonical).
func (s *Scheme) Digest() string { return s.digest }

// The file format. Level references are a level's name or its position (a number), so a preset can
// refer to a level without spelling a banner word.
type fileScheme struct {
	Schema     string        `json:"schema"`
	Name       string        `json:"name"`
	Version    int           `json:"version"`
	Vocabulary string        `json:"vocabulary,omitempty"`
	Note       string        `json:"note,omitempty"`
	Levels     []fileLevel   `json:"levels,omitempty"`
	LevelsFrom string        `json:"levelsFrom,omitempty"`
	Groups     []fileGroup   `json:"groups"`
	Retired    []fileRetired `json:"retired,omitempty"`
}

type fileLevel struct {
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
}

type levelRef = json.RawMessage

type fileGroup struct {
	Name             string              `json:"name"`
	Kind             string              `json:"kind"`
	Position         int                 `json:"position"`
	First            bool                `json:"first,omitempty"`
	Levels           []levelRef          `json:"levels,omitempty"`
	MinLevel         levelRef            `json:"minLevel,omitempty"`
	AbsorbedFrom     levelRef            `json:"absorbedFrom,omitempty"`
	Prefix           string              `json:"prefix,omitempty"`
	SpecifiedPrefix  string              `json:"specifiedPrefix,omitempty"`
	Tokens           []fileToken         `json:"tokens,omitempty"`
	TokensFrom       []fileTokensFrom    `json:"tokensFrom,omitempty"`
	Home             string              `json:"home,omitempty"`
	NoReleasePortion string              `json:"noReleasePortion,omitempty"`
	RestrictedFrom   levelRef            `json:"restrictedFrom,omitempty"`
	ReleaseLine      string              `json:"releaseLine,omitempty"`
	DisplayLine      string              `json:"displayLine,omitempty"`
	InGroup          string              `json:"inGroup,omitempty"`
	Countries        []string            `json:"countries,omitempty"`
	CountriesFrom    string              `json:"countriesFrom,omitempty"`
	Tetragraphs      map[string][]string `json:"tetragraphs,omitempty"`
	TetragraphsFrom  string              `json:"tetragraphsFrom,omitempty"`
	Source           string              `json:"source,omitempty"`
}

type fileToken struct {
	Token    string     `json:"token"`
	Portion  string     `json:"portion,omitempty"`
	MinLevel levelRef   `json:"minLevel,omitempty"`
	Levels   []levelRef `json:"levels,omitempty"`
	Suffix   bool       `json:"suffix,omitempty"`
	Reason   string     `json:"reason,omitempty"`
}

// fileTokensFrom takes tokens from the preset's vocabulary file by JSON pointer: a list of words,
// or of [banner, portion] pairs. A word met twice in one group keeps one entry with both entries'
// levels, and both must agree on the portion.
type fileTokensFrom struct {
	Pointer string     `json:"pointer"`
	Levels  []levelRef `json:"levels,omitempty"`
	Variant string     `json:"variant,omitempty"`
	Suffix  bool       `json:"suffix,omitempty"`
}

type fileRetired struct {
	Token      string `json:"token,omitempty"`
	TokensFrom string `json:"tokensFrom,omitempty"`
	Message    string `json:"message"`
}

// freeText is a reason, source, note or message: printable ASCII, at most 1024 bytes.
func freeText(s string) bool { return len(s) <= 1024 && printable.MatchString(s) }

// Bounds on a scheme file.
const (
	maxSchemeBytes = 256 << 10
	maxLevels      = 16
	maxGroups      = 64
	maxTokens      = 4096
	maxCountries   = 400
)

var (
	// schemeWord is a word a banner may carry: it starts and ends with a letter, digit or hyphen,
	// because a banner is trimmed before it is read, so "LOW " would read as "LOW".
	schemeWord = regexp.MustCompile(`^[A-Z0-9](?:[A-Z0-9 -]{0,62}[A-Z0-9-])?$`)
	groupName  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	printable  = regexp.MustCompile(`^[\x20-\x7e]*$`)
	pointer    = regexp.MustCompile(`^(/[a-z_]+)+$`)
)

// wholeNumber is every number a scheme may hold: versions, positions and levels.
var wholeNumber = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})$`)

//go:embed schemes/*.json tokens.json
var presetFiles embed.FS

// Preset loads a built-in scheme by name.
func Preset(name string) (*Scheme, error) {
	if !groupName.MatchString(name) {
		return nil, fmt.Errorf("unknown marking scheme preset %q", name)
	}
	raw, err := presetFiles.ReadFile("schemes/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("unknown marking scheme preset %q", name)
	}
	return load(name+".json", raw, true)
}

// LoadScheme reads a deployment's scheme file. It must be self-contained: only presets read a
// vocabulary file.
func LoadScheme(name string, raw []byte) (*Scheme, error) { return load(name, raw, false) }

func load(file string, raw []byte, preset bool) (*Scheme, error) {
	fail := func(path, format string, a ...any) (*Scheme, error) {
		return nil, fmt.Errorf("marking scheme %s: %s: %s", file, path, fmt.Sprintf(format, a...))
	}
	if len(raw) > maxSchemeBytes {
		return fail("$", "larger than %d bytes", maxSchemeBytes)
	}
	if err := noDuplicateKeys(raw, schemeFields); err != nil {
		return fail("$", "%v", err)
	}
	var f fileScheme
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		return fail("$", "not a scheme: %v", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fail("$", "trailing data")
	}
	if f.Schema != "badger.marking-scheme/v1" {
		return fail("schema", "must be badger.marking-scheme/v1")
	}
	if !freeText(f.Note) {
		return fail("note", "only printable ASCII, at most 1024 bytes")
	}
	if !groupName.MatchString(f.Name) || f.Version < 1 {
		return fail("name", "a scheme needs a lower-case name and a version of at least 1")
	}
	var vocab any
	if f.Vocabulary != "" || f.LevelsFrom != "" {
		if !preset || f.Vocabulary != "tokens.json" {
			return fail("vocabulary", "only a built-in preset reads a vocabulary file")
		}
		b, _ := presetFiles.ReadFile(f.Vocabulary)
		if err := json.Unmarshal(b, &vocab); err != nil {
			return fail("vocabulary", "%v", err)
		}
	}
	at := func(p string) (any, error) {
		if vocab == nil || !pointer.MatchString(p) {
			return nil, fmt.Errorf("pointer %q needs a preset vocabulary", p)
		}
		v := vocab
		for _, k := range strings.Split(p[1:], "/") {
			m, ok := v.(map[string]any)
			if !ok || m[k] == nil {
				return nil, fmt.Errorf("pointer %q does not resolve", p)
			}
			v = m[k]
		}
		return v, nil
	}
	s := &Scheme{Name: f.Name, Version: f.Version}
	levels := f.Levels
	if f.LevelsFrom != "" {
		if len(levels) > 0 {
			return fail("levelsFrom", "levels are given twice")
		}
		v, err := at(f.LevelsFrom)
		list, _ := v.([]any)
		if err != nil || list == nil {
			return fail("levelsFrom", "not a list of levels")
		}
		for _, l := range list {
			m, _ := l.(map[string]any)
			name, _ := m["banner"].(string)
			levels = append(levels, fileLevel{Name: name})
		}
	}
	if len(levels) < 2 || len(levels) > maxLevels {
		return fail("levels", "a scheme has between 2 and %d levels", maxLevels)
	}
	for i, l := range levels {
		if !schemeWord.MatchString(l.Name) || !freeText(l.Reason) {
			return fail(fmt.Sprintf("levels[%d]", i), "level name %q is not a banner word", l.Name)
		}
		if slices.ContainsFunc(s.Levels, func(x Level) bool { return x.Name == l.Name }) {
			return fail(fmt.Sprintf("levels[%d]", i), "level %q appears twice", l.Name)
		}
		s.Levels = append(s.Levels, Level{Name: l.Name})
	}
	level := func(r levelRef) (int, error) {
		// null would unmarshal into either form as its zero value: level 0, or the name "".
		if string(bytes.TrimSpace(r)) == "null" {
			return 0, errors.New("a level is a name or a position, never null")
		}
		var n int
		if json.Unmarshal(r, &n) == nil {
			if n < 0 || n >= len(s.Levels) {
				return 0, fmt.Errorf("no level at position %d", n)
			}
			return n, nil
		}
		var name string
		if json.Unmarshal(r, &name) != nil {
			return 0, errors.New("a level is a name or a position")
		}
		i := slices.IndexFunc(s.Levels, func(l Level) bool { return l.Name == name })
		if i < 0 {
			return 0, fmt.Errorf("no level %q", name)
		}
		return i, nil
	}
	optLevel := func(r levelRef) (int, error) {
		if len(r) == 0 {
			return -1, nil
		}
		return level(r)
	}
	levelList := func(rs []levelRef, min levelRef) ([]int, error) {
		var out []int
		for _, r := range rs {
			n, err := level(r)
			if err != nil {
				return nil, err
			}
			if slices.Contains(out, n) {
				return nil, fmt.Errorf("level %d listed twice", n)
			}
			out = append(out, n)
		}
		if len(min) > 0 {
			if len(out) > 0 {
				return nil, errors.New("levels and minLevel are given together")
			}
			m, err := level(min)
			if err != nil {
				return nil, err
			}
			for n := m; n < len(s.Levels); n++ {
				out = append(out, n)
			}
		}
		slices.Sort(out)
		return out, nil
	}
	if len(f.Groups) > maxGroups {
		return fail("groups", "more than %d groups", maxGroups)
	}
	tokens := 0
	for gi, fg := range f.Groups {
		path := fmt.Sprintf("groups[%d]", gi)
		// A deployment's file uses the plain shapes only: ordered levels and require groups of
		// literal tokens, with minimum levels, sub-compartments and opaque prefixes. Release lists,
		// sourced groups, specified variants, absorption, portion marks and retired markings are
		// for the built-in presets, whose tables are reviewed with the code. A smaller format is
		// a smaller target.
		if !preset {
			plain := fg.Kind == "require" && fg.SpecifiedPrefix == "" && len(fg.AbsorbedFrom) == 0 && !fg.First &&
				!slices.ContainsFunc(fg.Tokens, func(t fileToken) bool { return t.Portion != "" })
			if !plain {
				return fail(path, "a deployment scheme has require groups of tokens only (levels, minimum levels, sub-compartments, prefixes); release lists, sourced groups, specified variants, absorption and portion marks belong to the built-in presets")
			}
		}
		g := Group{Name: fg.Name, Kind: fg.Kind, Position: fg.Position, First: fg.First, Prefix: fg.Prefix,
			SpecifiedPrefix: fg.SpecifiedPrefix, Home: fg.Home, ReleaseLine: fg.ReleaseLine, DisplayLine: fg.DisplayLine, InGroup: fg.InGroup}
		if !groupName.MatchString(fg.Name) || slices.ContainsFunc(s.Groups, func(x Group) bool { return x.Name == fg.Name }) {
			return fail(path, "group name %q is not a lower-case name, or repeats", fg.Name)
		}
		if !freeText(fg.Source) {
			return fail(path+".source", "only printable ASCII")
		}
		var err error
		if g.Levels, err = levelList(fg.Levels, fg.MinLevel); err != nil {
			return fail(path+".levels", "%v", err)
		}
		if g.AbsorbedFrom, err = optLevel(fg.AbsorbedFrom); err != nil {
			return fail(path+".absorbedFrom", "%v", err)
		}
		if g.RestrictedFrom, err = optLevel(fg.RestrictedFrom); err != nil {
			return fail(path+".restrictedFrom", "%v", err)
		}
		if fg.Position < 1 || slices.ContainsFunc(s.Groups, func(x Group) bool {
			return x.Position == fg.Position && x.InGroup != fg.Name && fg.InGroup != x.Name
		}) {
			return fail(path+".position", "a position of at least 1 that no other group has")
		}
		for _, w := range []string{fg.Prefix, fg.SpecifiedPrefix, fg.Home, fg.ReleaseLine, fg.DisplayLine} {
			if w != "" && !schemeWord.MatchString(strings.TrimSuffix(w, "-")) {
				return fail(path, "%q is not a banner word", w)
			}
		}
		add := func(t Token, merge bool) error {
			if !schemeWord.MatchString(t.Token) || (t.Portion != "" && !schemeWord.MatchString(t.Portion)) {
				return fmt.Errorf("token %q is not a banner word", t.Token)
			}
			if slices.ContainsFunc(s.Levels, func(l Level) bool { return l.Name == t.Token }) {
				return fmt.Errorf("token %q is a level name", t.Token)
			}
			if i := slices.IndexFunc(g.Tokens, func(x Token) bool { return x.Token == t.Token }); i >= 0 {
				if !merge || g.Tokens[i].Portion != t.Portion {
					return fmt.Errorf("token %q appears twice", t.Token)
				}
				g.Tokens[i].Levels = unionLevels(levelWords(g.Tokens[i].Levels, len(s.Levels)), levelWords(t.Levels, len(s.Levels)))
				return nil
			}
			g.Tokens = append(g.Tokens, t)
			return nil
		}
		// A group with a specified prefix needs every token's variant; no other group takes one.
		variant := func(v string) error {
			if !slices.Contains([]string{"", "basic", "specified", "either"}, v) || (v != "") != (fg.SpecifiedPrefix != "") {
				return fmt.Errorf("variant %q needs a group with a specified prefix, and only such a group takes variants", v)
			}
			return nil
		}
		for ti, ft := range fg.Tokens {
			lv, err := levelList(ft.Levels, ft.MinLevel)
			if err == nil && !freeText(ft.Reason) {
				err = errors.New("reason: only printable ASCII")
			}
			if err == nil && fg.SpecifiedPrefix != "" {
				err = errors.New("a group with a specified prefix takes its tokens from the vocabulary")
			}
			if err == nil {
				err = add(Token{Token: ft.Token, Portion: ft.Portion, Levels: lv, Suffix: ft.Suffix}, false)
			}
			if err != nil {
				return fail(fmt.Sprintf("%s.tokens[%d]", path, ti), "%v", err)
			}
		}
		for ti, from := range fg.TokensFrom {
			fpath := fmt.Sprintf("%s.tokensFrom[%d]", path, ti)
			lv, err := levelList(from.Levels, nil)
			if err != nil {
				return fail(fpath, "%v", err)
			}
			if err := variant(from.Variant); err != nil {
				return fail(fpath, "%v", err)
			}
			v, err := at(from.Pointer)
			if err != nil {
				return fail(fpath, "%v", err)
			}
			list, _ := v.([]any)
			for _, e := range list {
				t := Token{Levels: lv, Variant: from.Variant, Suffix: from.Suffix}
				switch w := e.(type) {
				case string:
					t.Token = w
				case []any:
					if len(w) == 2 {
						t.Token, _ = w[0].(string)
						t.Portion, _ = w[1].(string)
					}
				}
				if err := add(t, true); err != nil {
					return fail(fpath, "%v", err)
				}
			}
		}
		for i := range g.Tokens {
			// Containment first: a token listed at every level is still refused in a group that
			// allows fewer.
			if lv := g.Tokens[i].Levels; len(lv) > 0 && len(g.Levels) > 0 && len(intersectLevels(lv, g.Levels)) != len(lv) {
				return fail(path, "token %q is allowed at a level its group is not", g.Tokens[i].Token)
			}
			if len(g.Tokens[i].Levels) == len(s.Levels) {
				g.Tokens[i].Levels = nil // every level: the same as unset
			}
		}
		tokens += len(g.Tokens)
		releaseFields := fg.Home != "" || fg.NoReleasePortion != "" || len(fg.RestrictedFrom) > 0 || fg.ReleaseLine != "" ||
			fg.DisplayLine != "" || fg.InGroup != "" || len(fg.Countries) > 0 || fg.CountriesFrom != "" ||
			len(fg.Tetragraphs) > 0 || fg.TetragraphsFrom != ""
		switch {
		case releaseFields && g.Kind != "release":
			return fail(path, "only a release group takes home, lines, countries, inGroup or restrictedFrom")
		case g.Kind != "require" && (len(fg.AbsorbedFrom) > 0 || fg.Prefix != "" || fg.SpecifiedPrefix != "" || fg.First):
			return fail(path, "only a require group takes absorbedFrom, prefix, specifiedPrefix or first")
		case g.Prefix != "" && len(g.Tokens) > 0:
			return fail(path, "a prefix group takes no tokens")
		case g.Kind == "release" && len(g.Tokens) > 0:
			return fail(path, "a release group takes no tokens")
		}
		switch g.Kind {
		case "require":
			if len(g.Tokens) == 0 && g.Prefix == "" {
				return fail(path, "a require group needs tokens or a prefix")
			}
		case "sourced":
			if len(g.Tokens) != 1 {
				return fail(path, "a sourced group has exactly one token")
			}
		case "release":
			if g.Countries, err = stringList(fg.Countries, fg.CountriesFrom, at); err != nil {
				return fail(path+".countries", "%v", err)
			}
			if g.Tetragraphs, err = tetragraphs(fg.Tetragraphs, fg.TetragraphsFrom, at); err != nil {
				return fail(path+".tetragraphs", "%v", err)
			}
			if len(g.Countries) == 0 || len(g.Countries) > maxCountries || !slices.Contains(g.Countries, g.Home) ||
				g.ReleaseLine == "" || g.DisplayLine == "" {
				return fail(path, "a release group needs a home country among at most %d countries and both lines", maxCountries)
			}
			// A banner part is read as a release line before a display line, so lines that are equal,
			// or where one begins the other, would grant release to countries listed for display only.
			if r, d := g.ReleaseLine+" ", g.DisplayLine+" "; strings.HasPrefix(r, d) || strings.HasPrefix(d, r) {
				return fail(path, "the release and display lines must differ, and neither may begin the other")
			}
			for _, c := range g.Countries {
				if !schemeWord.MatchString(c) || strings.Contains(c, " ") {
					return fail(path, "country %q is not a code", c)
				}
			}
			for name, members := range g.Tetragraphs {
				if slices.Contains(g.Countries, name) || !schemeWord.MatchString(name) {
					return fail(path, "tetragraph %q is a country or not a code", name)
				}
				for _, m := range members {
					if !slices.Contains(g.Countries, m) {
						return fail(path, "tetragraph %s member %q is not a known country", name, m)
					}
				}
			}
			if fg.NoReleasePortion == "" {
				return fail(path+".noReleasePortion", "a release group names its no-release token by portion")
			}
			g.NoRelease = fg.NoReleasePortion // resolved below, once every group is read
		default:
			return fail(path+".kind", "unknown group kind %q", g.Kind)
		}
		s.Groups = append(s.Groups, g)
	}
	if tokens > maxTokens {
		return fail("groups", "more than %d tokens", maxTokens)
	}
	for gi := range s.Groups {
		g := &s.Groups[gi]
		if g.InGroup != "" && !slices.ContainsFunc(s.Groups, func(x Group) bool { return x.Name == g.InGroup && x.Kind == "require" }) {
			return fail(fmt.Sprintf("groups[%d].inGroup", gi), "no require group %q", g.InGroup)
		}
		if g.Kind == "release" {
			found, in, owners := "", "", 0
			for _, x := range s.Groups {
				for _, t := range x.Tokens {
					if t.Portion == g.NoRelease && x.Kind == "require" {
						found, in, owners = t.Token, x.Name, owners+1
					}
				}
			}
			if found == "" {
				return fail(fmt.Sprintf("groups[%d].noReleasePortion", gi), "no require token has portion %q", g.NoRelease)
			}
			// One group owns the no-release token, so a label carries it, or not, in one place.
			if owners > 1 {
				return fail(fmt.Sprintf("groups[%d].noReleasePortion", gi), "the no-release token %q is in %d groups; it must be in one", found, owners)
			}
			g.NoRelease, g.noReleaseIn = found, in
		}
	}
	kinds := map[string]int{}
	portions := map[string]string{}
	for _, g := range s.Groups {
		kinds[g.Kind]++
		for _, t := range g.Tokens {
			if other, ok := portions[t.Portion]; ok && t.Portion != "" && other != t.Token {
				return fail("groups", "portion %q stands for both %q and %q", t.Portion, other, t.Token)
			}
			portions[t.Portion] = t.Token
		}
	}
	if kinds["release"] > 1 || kinds["sourced"] > 1 || kinds["sourced"] > kinds["release"] {
		return fail("groups", "at most one release group, and at most one sourced group, which needs the release group's countries")
	}
	if err := unambiguous(s); err != nil {
		return fail("groups", "%v", err)
	}
	if len(f.Retired) > 0 && !preset {
		return fail("retired", "retired markings belong to the built-in presets")
	}
	for ri, fr := range f.Retired {
		words := []string{fr.Token}
		if fr.TokensFrom != "" {
			var err error
			if fr.Token != "" {
				return fail(fmt.Sprintf("retired[%d]", ri), "token and tokensFrom are given together")
			}
			if words, err = stringList(nil, fr.TokensFrom, at); err != nil {
				return fail(fmt.Sprintf("retired[%d]", ri), "%v", err)
			}
		}
		for _, w := range words {
			if !schemeWord.MatchString(w) || fr.Message == "" || !freeText(fr.Message) {
				return fail(fmt.Sprintf("retired[%d]", ri), "a retired marking needs a banner word and a message")
			}
			s.Retired = append(s.Retired, Retired{Token: w, Message: fr.Message})
		}
	}
	sum := sha256.Sum256(canonical(s))
	s.digest = "sha256:" + hex.EncodeToString(sum[:])
	s.rules = s.clone()
	s.rules.rules = s.rules
	return s, nil
}

// form is one shape of word a require group accepts: a literal word, a token with an opaque
// "-X" sub-compartment, or an opaque identifier after a prefix. token is the token the shape
// stands for ("" for a prefix group or a release line).
type form struct {
	group, token, kind, text string // kind: "word", "suffix" or "prefix"
	levels                   []int
}

// forms lists every shape each group accepts, at the levels it accepts it.
func forms(s *Scheme) []form {
	var out []form
	for _, g := range s.Groups {
		glv := levelWords(g.Levels, len(s.Levels))
		switch g.Kind {
		case "sourced":
			w, lv := g.Tokens[0].Token, glv
			if len(g.Tokens[0].Levels) > 0 {
				lv = g.Tokens[0].Levels
			}
			out = append(out, form{g.Name, w, "prefix", w + " ", lv}, form{g.Name, w, "word", w, lv})
		case "release":
			// The release lines are read in the group that holds them, before its tokens.
			for _, line := range []string{g.ReleaseLine, g.DisplayLine} {
				out = append(out, form{g.InGroup + " lines", "", "prefix", line + " ", glv})
			}
		case "require":
			if g.Prefix != "" {
				out = append(out, form{g.Name, "", "prefix", g.Prefix, glv})
			}
			for _, t := range g.Tokens {
				lv := levelWords(t.Levels, len(s.Levels))
				if len(t.Levels) == 0 {
					lv = glv
				}
				// Each way the token is written: bare unless it is specified, with the specified
				// prefix when it is specified or either.
				var written []string
				if t.Variant != "specified" {
					written = append(written, t.Token)
				}
				if t.Variant == "specified" || t.Variant == "either" {
					written = append(written, g.SpecifiedPrefix+t.Token)
				}
				for _, w := range written {
					out = append(out, form{g.Name, t.Token, "word", w, lv})
					if t.Suffix {
						out = append(out, form{g.Name, t.Token, "suffix", w + "-", lv})
					}
				}
			}
		}
	}
	return out
}

// overlap reports whether some word could take both shapes. Prefixes and sub-compartments are
// compared as prefixes, conservatively: two shapes either of which starts the other overlap.
func overlap(a, b form) bool {
	switch {
	case a.kind == "word" && b.kind == "word":
		return a.text == b.text
	case a.kind == "word":
		return strings.HasPrefix(a.text, b.text) && len(a.text) > len(b.text)
	case b.kind == "word":
		return strings.HasPrefix(b.text, a.text) && len(b.text) > len(a.text)
	}
	return strings.HasPrefix(a.text, b.text) || strings.HasPrefix(b.text, a.text)
}

// unambiguous refuses one word that could stand for two things at a common level: two groups, or
// two tokens of one group. The parser could not tell which a banner means. Countries live inside
// release lines and are not compared.
func unambiguous(s *Scheme) error {
	fs := forms(s)
	for i, a := range fs {
		for _, b := range fs[i+1:] {
			// Two forms of one token may share a word only if they are the same form: a bare word and
			// the token with a sub-compartment that spells the same word mean different things.
			same := a.group == b.group && a.token == b.token && a.kind == b.kind && a.text == b.text
			// Across groups, levels decide which group a banner means, so disjoint levels are
			// enough. Within one group a word is looked up before its level is known, so any two
			// forms that can spell the same word are refused, whatever their levels.
			if same || !overlap(a, b) || a.group != b.group && len(intersectLevels(a.levels, b.levels)) == 0 {
				continue
			}
			if a.group == b.group && a.token == b.token {
				return fmt.Errorf("token %q of group %s can be read two ways (%q, %q)", a.token, a.group, a.text, b.text)
			}
			if a.group == b.group {
				return fmt.Errorf("tokens %q and %q of group %s can be written the same way (%q, %q)", a.token, b.token, a.group, a.text, b.text)
			}
			if a.kind == "word" && b.kind == "word" {
				return fmt.Errorf("token %q is in groups %s and %s at the same level", a.text, a.group, b.group)
			}
			return fmt.Errorf("groups %s and %s accept the same words (%q, %q) at the same level", a.group, b.group, a.text, b.text)
		}
	}
	return nil
}

// levelWords expands an empty level list to every level.
func levelWords(l []int, n int) []int {
	if len(l) > 0 {
		return l
	}
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	return all
}

func unionLevels(a, b []int) []int {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}

func intersectLevels(a, b []int) []int {
	var out []int
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func stringList(inline []string, from string, at func(string) (any, error)) ([]string, error) {
	if from == "" {
		return inline, nil
	}
	if len(inline) > 0 {
		return nil, errors.New("given twice")
	}
	v, err := at(from)
	if err != nil {
		return nil, err
	}
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		w, ok := e.(string)
		if !ok {
			return nil, errors.New("not a list of words")
		}
		out = append(out, w)
	}
	return out, nil
}

func tetragraphs(inline map[string][]string, from string, at func(string) (any, error)) (map[string][]string, error) {
	if from == "" {
		return inline, nil
	}
	if len(inline) > 0 {
		return nil, errors.New("given twice")
	}
	v, err := at(from)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	out := map[string][]string{}
	for k, members := range m {
		arr, _ := members.([]any)
		for _, e := range arr {
			w, ok := e.(string)
			if !ok {
				return nil, errors.New("not a list of words")
			}
			out[k] = append(out[k], w)
		}
	}
	return out, nil
}

// canonical is the scheme's semantic content as canonical JSON (RFC 8785: object keys sorted, no
// whitespace). Reasons, sources and notes are left out: they explain a table, they do not change
// what a label means, so editing them does not change the digest. Every string is printable ASCII
// (validated), so Go's encoder and the TypeScript port write the same bytes.
func canonical(s *Scheme) []byte {
	ints := func(l []int) []any {
		out := []any{}
		for _, n := range l {
			out = append(out, n)
		}
		return out
	}
	levels := []any{}
	for _, l := range s.Levels {
		levels = append(levels, l.Name)
	}
	groups := []any{}
	for _, g := range s.Groups {
		toks := []any{}
		for _, t := range g.Tokens {
			toks = append(toks, map[string]any{"token": t.Token, "portion": t.Portion, "levels": ints(t.Levels), "variant": t.Variant, "suffix": t.Suffix})
		}
		tetra := map[string]any{}
		for k, v := range g.Tetragraphs {
			members := slices.Clone(v)
			slices.Sort(members)
			tetra[k] = members
		}
		countries := g.Countries
		if countries == nil {
			countries = []string{}
		}
		group := map[string]any{
			"name": g.Name, "kind": g.Kind, "position": g.Position, "first": g.First, "levels": ints(g.Levels),
			"absorbedFrom": g.AbsorbedFrom, "prefix": g.Prefix, "specifiedPrefix": g.SpecifiedPrefix, "tokens": toks, "home": g.Home,
			"noRelease": g.NoRelease, "restrictedFrom": g.RestrictedFrom, "releaseLine": g.ReleaseLine,
			"displayLine": g.DisplayLine, "inGroup": g.InGroup, "countries": countries, "tetragraphs": tetra,
		}
		// When more than one group has a token spelled like the no-release token, the word does not
		// say which one restricts release, so the owner is part of the digest. Otherwise it is
		// implied, and leaving it out keeps the pinned digests of schemes that were already exact.
		holders := 0
		for _, x := range s.Groups {
			if g.NoRelease != "" && slices.ContainsFunc(x.Tokens, func(t Token) bool { return t.Token == g.NoRelease }) {
				holders++
			}
		}
		if holders > 1 {
			group["noReleaseIn"] = g.noReleaseIn
		}
		groups = append(groups, group)
	}
	retired := []any{}
	for _, r := range s.Retired {
		retired = append(retired, map[string]any{"token": r.Token, "message": r.Message})
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(map[string]any{"schema": "badger.marking-scheme/v1", "name": s.Name, "version": s.Version,
		"levels": levels, "groups": groups, "retired": retired})
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// schemeFields is every key the scheme format defines, in its one spelling.
var schemeFields = fieldNames(reflect.TypeFor[fileScheme]())

// fieldNames is every JSON key a file type defines, in its one spelling.
func fieldNames(root reflect.Type) map[string]bool {
	names := map[string]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		switch t.Kind() {
		case reflect.Slice, reflect.Map:
			walk(t.Elem())
		case reflect.Struct:
			for i := range t.NumField() {
				if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && !names[name] {
					names[name] = true
					walk(t.Field(i).Type)
				}
			}
		}
	}
	walk(root)
	return names
}

// noDuplicateKeys refuses a JSON document in which an object repeats a key. encoding/json keeps
// the last copy silently, so a table could say one thing to a reviewer and another to the parser.
// encoding/json also matches field names without regard to case, so a key that differs from a
// field name only in case is refused too, and two keys that differ only in case count as one.
func noDuplicateKeys(raw []byte, fieldNames map[string]bool) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if n, ok := t.(json.Number); ok && !wholeNumber.MatchString(string(n)) {
			// Bounding numbers keeps every reader exact: a JavaScript reader rounds integers past
			// 2^53, so two versions could share a digest, and reads 1e0 or 1.0 as 1 where
			// encoding/json refuses them. A policy holds no numbers at all.
			return fmt.Errorf("number %s is not a whole number from 0 to 999999", n)
		}
		switch t {
		case json.Delim('{'):
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, _ := k.(string)
				if keys[strings.ToLower(key)] {
					return fmt.Errorf("key %s appears twice in one object", strconv.Quote(key))
				}
				keys[strings.ToLower(key)] = true
				if !fieldNames[key] {
					for name := range fieldNames {
						if strings.EqualFold(name, key) {
							return fmt.Errorf("key %s is spelled %s", strconv.Quote(key), strconv.Quote(name))
						}
					}
				}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case nil:
			// null would decode as the zero value: an empty list, level 0, no restriction.
			return errors.New("a value is never null")
		case json.Delim('['):
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(); err != nil {
		if strings.Contains(err.Error(), "appears twice") || strings.Contains(err.Error(), "is spelled") || strings.Contains(err.Error(), "never null") || strings.Contains(err.Error(), "whole number") {
			return err
		}
		return errors.New("not JSON")
	}
	return nil
}
