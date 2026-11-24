// Package store holds the portal's narrow persistence interfaces and their implementation in
// the service's database (PG). A platform-backed deployment replaces the implementation, not the
// callers.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Version is one signed, immutable profile version.
type Version struct {
	ProfileID      string          `json:"profileId"`
	TenantID       string          `json:"tenantId"`
	DeploymentID   string          `json:"deploymentId"`
	Sequence       uint64          `json:"sequence"`
	NotBefore      string          `json:"notBefore"`
	ExpiresAt      string          `json:"expiresAt"`
	PayloadSHA256  string          `json:"payloadSha256"`
	EnvelopeSHA256 string          `json:"envelopeSha256"`
	SignerKeyIDs   []string        `json:"signerKeyIds"`
	CreatedAt      time.Time       `json:"createdAt"`
	CreatedBy      string          `json:"createdBy"`
	Envelope       json.RawMessage `json:"envelope,omitempty"`
}

var (
	ErrExists    = errors.New("version already exists")
	ErrProfileID = errors.New("profile ID is not an identifier")
	// ErrRollback: an assignment that would move a deployment to an older version, or to another
	// profile, over what is stored.
	ErrRollback = errors.New("a deployment never moves to an older version")
	// ErrAuditBroken: an append may or may not have reached disk, so the chain head is unknown.
	// The log refuses every append until an operator reopens it and checks the file.
	ErrAuditBroken = errors.New("audit log is in an unknown state after a failed append; reopen it")
)

type ProfileStore interface {
	// Put stores a new version; a stored sequence is never replaced.
	Put(Version) error
	Latest(profileID string) (Version, bool, error)
	// Versions returns every version of a profile, newest first.
	Versions(profileID string) ([]Version, error)
	Get(profileID string, sequence uint64) (Version, bool, error)
	// List returns the latest version of every profile, by profile ID.
	List() ([]Version, error)
}

// Assignment names the profile version a deployment (device group) runs. It is replaced, not
// versioned; the audit log keeps its history. PR 6 signs it as an activation record.
type Assignment struct {
	DeploymentID  string    `json:"deploymentId"`
	ProfileID     string    `json:"profileId"`
	Sequence      uint64    `json:"sequence"`
	PayloadSHA256 string    `json:"payloadSha256"`
	AssignedAt    time.Time `json:"assignedAt"`
	AssignedBy    string    `json:"assignedBy"`
}

type AssignmentStore interface {
	Assignment(deploymentID string) (Assignment, bool, error)
	PutAssignment(Assignment) error
}

// Record is one audit entry. Prev chains each entry to the hash of the line before it.
type Record struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Role   string    `json:"role"`
	Action string    `json:"action"`
	Object string    `json:"object"`
	Before string    `json:"before,omitempty"`
	After  string    `json:"after,omitempty"`
	Prev   string    `json:"prev"`
}

type AuditSink interface{ Append(Record) error }

// DeviceRegistry is implemented by the enrollment change (PORTAL.md, PR 4).
type DeviceRegistry interface {
	Assignment(deviceID string) (deploymentID string, revoked bool, err error)
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
