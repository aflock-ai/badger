// Package auth holds the principal and role types every portal package shares.
package auth

import "net/http"

type Role string

const (
	None     Role = ""
	Admin    Role = "admin"
	Approver Role = "approver"
	Auditor  Role = "auditor"
)

func (r Role) Valid() bool { return r == Admin || r == Approver || r == Auditor }

// Principal is an authenticated person. UserID is stable across name changes in the IdP.
type Principal struct {
	UserID string
	Name   string
	Role   Role
}

// Authenticator turns a request into a principal.
type Authenticator interface {
	Authenticate(*http.Request) (Principal, error)
}
