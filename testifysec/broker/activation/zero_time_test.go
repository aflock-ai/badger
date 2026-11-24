package activation

import (
	"errors"
	"testing"
)

// A record dated at Go's zero time would have its chain checked at the verifier's clock instead
// of its signed notBefore (x509.VerifyOptions treats a zero CurrentTime as now). It is refused as
// malformed before any certificate is looked at, as is anything before 2000.
func TestVerifyRefusesZeroAndAncientTimes(t *testing.T) {
	root := newRoot(t, "enclave root")
	leaf := signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN}
	for _, notBefore := range []string{"0001-01-01T00:00:00Z", "1999-12-31T23:59:59Z"} {
		body := activationBody(41, 12, 200, -60, 3600)
		body["notBefore"] = notBefore
		_, err := Verify(trustFor(root), envelope(t, ActivationType, body, leaf))
		var r Refusal
		if !errors.As(err, &r) || r != RefuseMalformed {
			t.Fatalf("notBefore %s: got %v, want malformed", notBefore, err)
		}
	}
}
