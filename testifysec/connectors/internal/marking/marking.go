// Package marking parses US classification and CUI banner markings into a structure with a
// dominance order, so a connector can label every result and the session can keep a high-water
// mark. It implements the banner structure and a versioned allowlist of tokens (tokens.json,
// each table citing its source), not the whole CAPCO register: an unknown token is an error,
// never a guess. Markings are labels for people and policy; they are not a security boundary.
package marking

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

// Levels, in dominance order. CUI sits above UNCLASSIFIED and below CONFIDENTIAL.
const (
	Unclassified = iota
	CUI
	Confidential
	Secret
	TopSecret
)

// Marking is one parsed banner. Set fields are sorted; RelTo and DisplayOnly keep banner order.
type Marking struct {
	Level       int
	SCI, SAP    []string
	AEA         []string
	FGI         []string // country codes after FGI; empty with HasFGI means the source is concealed
	HasFGI      bool
	Categories  []string // CUI categories as written, SP- prefix kept
	Controls    []string // dissemination controls, classified and CUI, without REL TO / DISPLAY ONLY
	NonIC       []string
	RelTo       []string // nil: no REL TO line
	DisplayOnly []string
	// Tags holds the require groups the fields above do not name, by group name, each sorted.
	// Nil under the us-gov scheme.
	Tags map[string][]string
	// scheme is the scheme the marking was read under; nil is the us-gov preset, so a Marking
	// built field by field is a us-gov marking.
	scheme *Scheme
}

//go:embed tokens.json
var tokensJSON []byte

type pairs [][2]string // banner, portion

var tab struct {
	Version int
	Levels  []struct{ Banner, Portion string }
	SCI     struct{ Tokens []string }
	SAP     struct{ Prefix string }
	AEA     struct{ Tokens []string }
	FGI     struct{ Token string }
	Dissem  struct{ Tokens pairs }
	NonIC   struct{ Tokens []string } `json:"nonic"`
	CUILDC  struct{ Tokens pairs }    `json:"cui_ldc"`
	CUICat  struct {
		Basic, Specified, Either []string
	} `json:"cui_categories"`
	Release struct {
		Countries   []string
		Tetragraphs map[string][]string
	}
	Legacy struct{ Tokens []string }
}

func init() {
	if err := json.Unmarshal(tokensJSON, &tab); err != nil || tab.Version != 1 {
		panic("marking: tokens.json: " + fmt.Sprint(err))
	}
}

// controlOrder is the canonical order of every dissemination control, classified first.
func controlOrder() pairs { return append(append(pairs{}, tab.Dissem.Tokens...), tab.CUILDC.Tokens...) }

// Parse reads a configured banner (full words, not portion abbreviations). Retired markings are
// refused here: an administrator must configure a current marking.
func Parse(s string) (Marking, error) { return process().parse(s) }

// bannerChars is everything a banner may hold. A marking is printed outside the untrusted-content
// block, so nothing else (a newline, a tag, an instruction in punctuation) may pass through it.
var bannerChars = regexp.MustCompile(`^[A-Z0-9 ,/-]{1,512}$`)

// maxBanner is the longest banner bannerChars accepts.
const maxBanner = 512

// sciToken is an SCI control system with an optional sub-compartment; sapToken a SAP identifier,
// which ends in a letter, digit or hyphen so a banner's trim cannot change it.
var (
	sciToken = regexp.MustCompile(`^[A-Z0-9]+(-[A-Z0-9]+)?$`)
	sapToken = regexp.MustCompile(`^[A-Z0-9](?:[A-Z0-9 -]{0,61}[A-Z0-9-])?$`)
)

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}

// String renders the canonical banner.
func (m Marking) String() string { return schemeOf(m).banner(m) }

// Bottom is the process scheme's lowest label: what a session that has read nothing holds.
func Bottom() Marking { return process().Bottom() }
