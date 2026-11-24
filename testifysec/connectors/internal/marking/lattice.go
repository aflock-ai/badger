package marking

import (
	"maps"
	"slices"
)

// Lattice is a marking in the form a database compares without the token tables: every set sorted
// and never nil, and the foreign release and display lists expanded to countries (Release or
// Display nil means unrestricted). Dominates(a, b) holds exactly when LatticeOf(a) dominates
// LatticeOf(b) by these rules: level at least; SCI, SAP, AEA, non-IC and dissemination controls a
// superset; FGI held when b has it (concealed FGI only by concealed FGI); below CONFIDENTIAL the
// controlled-unclassified categories a superset; Release and Display a subset (nil is everything);
// Tags a superset. Tags is "group/token" for every require group a field above does not name
// (another scheme's groups); it is left out when empty, so a us-gov lattice is as it was. The
// rule holds for schemes that absorb no group or, like us-gov, only the categories from level 2.
type Lattice struct {
	Level      int      `json:"level"`
	SCI        []string `json:"sci"`
	SAP        []string `json:"sap"`
	AEA        []string `json:"aea"`
	NonIC      []string `json:"nonic"`
	Controls   []string `json:"controls"`
	HasFGI     bool     `json:"has_fgi"`
	FGI        []string `json:"fgi"`
	Categories []string `json:"categories"`
	Release    []string `json:"release"`
	Display    []string `json:"display"`
	Tags       []string `json:"tags,omitempty"`
	// Scheme is the digest of the scheme the marking was read under, left out for us-gov. Two
	// lattices compare only when their schemes are equal; with different schemes neither
	// dominates the other.
	Scheme string `json:"scheme,omitempty"`
}

// LatticeOf is m's comparable form.
func LatticeOf(m Marking) Lattice {
	set := func(s []string) []string {
		if len(s) == 0 {
			return []string{}
		}
		return sorted(s)
	}
	keys := func(s map[string]bool) []string {
		if s == nil {
			return nil // unrestricted
		}
		// An empty restriction (release to nobody) is the most restrictive, never unrestricted.
		return append([]string{}, slices.Sorted(maps.Keys(s))...)
	}
	var tags []string
	for g, l := range m.Tags {
		for _, t := range l {
			tags = append(tags, g+"/"+t)
		}
	}
	slices.Sort(tags)
	s := schemeOf(m)
	return Lattice{Level: m.Level, SCI: set(m.SCI), SAP: set(m.SAP), AEA: set(m.AEA), NonIC: set(m.NonIC),
		Controls: set(m.Controls), HasFGI: m.HasFGI, FGI: set(m.FGI), Categories: set(m.Categories),
		Release: keys(s.release(m)), Display: keys(s.display(m)), Tags: tags, Scheme: schemeDigestField(m)}
}

// ControlForPortion is the banner word of the token whose portion mark is p.
func ControlForPortion(p string) (string, bool) { return process().forPortion(p) }

// schemeDigestField is a lattice's scheme: empty for us-gov, so a us-gov lattice is as it was.
func schemeDigestField(m Marking) string {
	if m.scheme == nil {
		return ""
	}
	return m.scheme.digest
}
