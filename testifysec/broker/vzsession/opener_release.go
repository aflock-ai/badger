//go:build !uatsignin

package vzsession

// headlessSignIn is false in every build but the session UAT's: sign-in opens the person's browser.
const headlessSignIn = false
