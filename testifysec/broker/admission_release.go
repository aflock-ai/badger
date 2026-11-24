//go:build !uatnoprofile

package main

// developmentNoProfile is false in every build but the uatnoprofile one: a release broker has no
// path that runs a request without a verified profile, whatever its policy says.
const developmentNoProfile = false
