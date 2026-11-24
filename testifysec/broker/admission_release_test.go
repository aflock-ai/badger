//go:build !uatnoprofile

// jade:ring local

package main

import (
	"context"
	"testing"
)

// In a release build no policy and no request reaches a session without a verified profile (#160):
// the development flag alone neither admits a request with no envelope nor loads a policy that
// names no verifier.
func TestReleaseHasNoUnsignedPath(t *testing.T) {
	if developmentNoProfile {
		t.Fatal("a build without the uatnoprofile tag allows running with no profile")
	}
	if _, err := verifyAdmission(context.Background(), policy{DevelopmentAllowSameUID: true}, ""); err == nil {
		t.Fatal("request with no profile admitted under the development flag")
	}
	if _, _, err := loadPolicy(writePolicy(t, testPolicy(t))); err == nil {
		t.Fatal("development policy without a verifier loaded")
	}
}
