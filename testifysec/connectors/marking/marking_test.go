package marking

import (
	"testing"

	internal "github.com/aflock-ai/badger/testifysec/connectors/internal/marking"
)

// The wrapper is the internal package: same parse, order and rendering.
func TestWrapperMatchesInternal(t *testing.T) {
	secret, err := Parse("SECRET//REL TO USA, GBR")
	if err != nil {
		t.Fatal(err)
	}
	top, err := Parse("TOP SECRET//SI")
	if err != nil {
		t.Fatal(err)
	}
	j, err := Join(top, secret)
	if err != nil || !Dominates(top, secret) || Dominates(secret, top) || !Dominates(j, secret) {
		t.Error("dominance", err)
	}
	if got := Banner(j); got != "TOP SECRET//SI" {
		t.Errorf("Banner(Join) = %q", got)
	}
	fgi, err := Parse("UNCLASSIFIED//FGI GBR")
	if err != nil {
		t.Fatal(err)
	}
	controlled := Marking{Level: internal.Unclassified + 1} // the controlled-unclassified level
	if _, err := Join(fgi, controlled); err != ErrNoBanner {
		t.Errorf("Join refused with %v", err)
	}
	if _, err := Parse("SECRET//NOT A TOKEN"); err == nil {
		t.Error("unknown token accepted")
	}
}
