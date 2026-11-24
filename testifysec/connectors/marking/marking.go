// Package marking is the public face of the connectors' classification-marking parser, for other
// Badger modules (the native gateway's request-label check) that need the same parsing and
// dominance order the connectors use. It re-exports internal/marking unchanged; the parser, its
// token tables and their sources live there. See testifysec/CONNECTORS.md, "Classification
// markings".
package marking

import "github.com/aflock-ai/badger/testifysec/connectors/internal/marking"

// Marking is one parsed banner.
type Marking = marking.Marking

// Parse reads a configured banner (full words); retired markings and unknown tokens are errors.
func Parse(banner string) (Marking, error) { return marking.Parse(banner) }

// Dominates reports whether a sink accredited at a may hold content marked b (no write down).
func Dominates(a, b Marking) bool { return marking.Dominates(a, b) }

// ErrNoBanner is Join's refusal: a and b combine to a marking that no banner prints.
var ErrNoBanner = marking.ErrNoBanner

// ErrBannerTooLong is Join's refusal when the joined banner would be longer than Parse accepts.
var ErrBannerTooLong = marking.ErrBannerTooLong

// Join is an upper bound of a and b: the high-water update after reading both. It returns
// ErrNoBanner when the combination is controlled unclassified information with FGI,
// atomic-energy or non-IC markings, and ErrBannerTooLong when the joined banner would be longer
// than Parse accepts.
func Join(a, b Marking) (Marking, error) { return marking.Join(a, b) }

// Banner renders m as its canonical banner line.
func Banner(m Marking) string { return m.String() }

// Lattice is a marking in the form a database compares without the token tables.
type Lattice = marking.Lattice

// LatticeOf is m's comparable form: Dominates(a, b) holds exactly when LatticeOf(a) dominates
// LatticeOf(b) by the rules on Lattice.
func LatticeOf(m Marking) Lattice { return marking.LatticeOf(m) }

// ControlForPortion is the banner word of the dissemination control whose portion mark is p.
func ControlForPortion(p string) (string, bool) { return marking.ControlForPortion(p) }

// Scheme is a classification scheme: an ordered list of levels and the groups a banner may carry.
type Scheme = marking.Scheme

// Preset loads a built-in scheme by name: "us-gov" (the default) or "corporate".
func Preset(name string) (*Scheme, error) { return marking.Preset(name) }

// LoadScheme reads a deployment's scheme file, refusing anything ambiguous or malformed.
func LoadScheme(name string, raw []byte) (*Scheme, error) { return marking.LoadScheme(name, raw) }

// Configure sets this process's scheme once, before any label is read; a change is refused.
func Configure(s *Scheme) error { return marking.Configure(s) }

// Bottom is the process scheme's lowest label.
func Bottom() Marking { return marking.Bottom() }

// ErrSchemeMismatch is Join's refusal for markings read under different schemes.
var ErrSchemeMismatch = marking.ErrSchemeMismatch

// Policy is a deployment's marking policy: its scheme, the markings of its data sources and its
// deny-only flow rules.
type Policy = marking.Policy

// LoadPolicy reads a marking policy; scheme resolves a scheme file the policy names.
func LoadPolicy(name string, raw []byte, scheme func(file string) ([]byte, error)) (*Policy, error) {
	return marking.LoadPolicy(name, raw, scheme)
}

// ErrUnmapped is Classify's refusal for a source no glob matches when the policy refuses those.
var ErrUnmapped = marking.ErrUnmapped

// Current is the scheme this process uses: the one Configure set, or us-gov.
func Current() *Scheme { return marking.Current() }

// DigestOf is the digest of the scheme a marking was read under.
func DigestOf(m Marking) string { return marking.DigestOf(m) }
