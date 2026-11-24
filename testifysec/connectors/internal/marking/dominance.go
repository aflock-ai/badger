package marking

import (
	"errors"
	"slices"
)

// ErrNoBanner is Join's refusal: the two markings combine to controlled-unclassified content
// holding FGI, atomic-energy or non-IC markings, which no banner prints.
var ErrNoBanner = errors.New("these markings cannot be combined: no banner prints controlled unclassified information with FGI, atomic-energy or non-IC markings")

// ErrBannerTooLong is Join's other refusal: the joined banner would be longer than Parse accepts,
// so it would not read back.
var ErrBannerTooLong = errors.New("these markings cannot be combined: their joined banner would be longer than 512 characters")

// Dominates reports whether a system or sink accredited at a may hold content marked b (no
// write down), by the process scheme's rules (engine.go, Scheme.dominates). A marking read under
// another scheme dominates nothing and is dominated by nothing.
func Dominates(a, b Marking) bool { return process().Dominates(a, b) }

// Join is a marking that dominates both: the session high-water mark after reading from
// connectors marked a and b, by the process scheme's rules (engine.go, Scheme.join). It returns
// ErrNoBanner when the joined level does not allow a group the join carries, and ErrBannerTooLong
// when its banner would be longer than Parse accepts, and ErrSchemeMismatch when either marking
// was read under another scheme.
func Join(a, b Marking) (Marking, error) { return process().Join(a, b) }

// subset treats nil as the universe.
func subset(a, b map[string]bool) bool {
	if b == nil {
		return true
	}
	if a == nil {
		return false
	}
	for c := range a {
		if !b[c] {
			return false
		}
	}
	return true
}

func superset(a, b []string) bool {
	return !slices.ContainsFunc(b, func(x string) bool { return !slices.Contains(a, x) })
}

func union(a, b []string) []string {
	if len(a)+len(b) == 0 {
		return nil
	}
	return sorted(append(slices.Clone(a), b...))
}
