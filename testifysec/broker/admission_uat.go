//go:build uatnoprofile

package main

// developmentNoProfile lets a broker built with -tags uatnoprofile run unsigned sandbox-only
// fixtures when its policy sets developmentAllowSameUID and names no verifier. Only the local
// UAT builds this; see README.md.
const developmentNoProfile = true
