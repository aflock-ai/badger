// Package platformsession authenticates an enrolled agent against live platform
// state. Authentication never grants model, tool, signing or upload authority.
package platformsession

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const EndpointPath = "/api/agent/session-check"
const Purpose = "agent-session-identity"

var ErrRefused = errors.New("platform refused the agent session")
var ErrUnavailable = errors.New("platform agent session unavailable")
var ErrInvalid = errors.New("invalid platform session configuration or response")
var ErrCurrentHumanAssuranceUnsupported = errors.New("current human assurance requires a separate supported ceremony")

// Config is administrator-provisioned. It contains paths, never credential
// bytes. CAFile is an explicit trust bundle, independent of inherited proxy and
// system-root environment. The repository is a platform ProductRepository UUID,
// not a renameable URL, product UUID or provider-specific numeric ID.
type Config struct {
	Endpoint               string `json:"endpoint"`
	CAFile                 string `json:"caFile"`
	CredentialFile         string `json:"credentialFile"`
	TenantID               string `json:"tenantID"`
	AgentID                string `json:"agentID"`
	RepositoryID           string `json:"repositoryID"`
	TrustDomain            string `json:"trustDomain"`
	MinimumEnrollmentAAL   string `json:"minimumEnrollmentAAL"`
	RequireCurrentHumanAAL string `json:"requireCurrentHumanAAL"`
}

// Delegation records a historical enrollment reference. It never identifies the
// currently present human, proves a current Kratos session or grants API access.
type Delegation struct {
	Source           string `json:"source"`
	UserID           string `json:"user_id"`
	IdentityID       string `json:"identity_id"`
	EnrollmentAAL    string `json:"enrollment_aal"`
	EnrollmentGitoid string `json:"enrollment_gitoid"`
	HumanPresence    string `json:"human_presence"`
}

type Identity struct {
	Schema          string     `json:"schema"`
	Purpose         string     `json:"purpose"`
	Authenticated   bool       `json:"authenticated"`
	Authorization   string     `json:"authorization"`
	TenantID        string     `json:"tenant_id"`
	AgentID         string     `json:"agent_id"`
	RepositoryID    string     `json:"repository_id"`
	RepositoryScope string     `json:"repository_scope"`
	SPIFFEID        string     `json:"spiffe_id"`
	Nonce           string     `json:"nonce"`
	CheckedAt       time.Time  `json:"checked_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	Delegation      Delegation `json:"delegation"`
}

type Client struct {
	config Config
	http   *http.Client
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
var credentialPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

func validID(value string) bool {
	return uuidPattern.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}

func assurance(value string) int {
	switch value {
	case "aal1":
		return 1
	case "aal2":
		return 2
	case "aal3":
		return 3
	default:
		return 0
	}
}

func New(c Config) (*Client, error) {
	if c.RequireCurrentHumanAAL != "" {
		return nil, ErrCurrentHumanAssuranceUnsupported
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != EndpointPath || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !validID(c.TenantID) || !validID(c.AgentID) || !validID(c.RepositoryID) || !domainPattern.MatchString(c.TrustDomain) || strings.Contains(c.TrustDomain, "..") || assurance(c.MinimumEnrollmentAAL) == 0 {
		return nil, ErrInvalid
	}
	b, err := privateFile(c.CAFile, 1024*1024)
	if err != nil {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return nil, ErrInvalid
	}
	if _, err := readCredential(c.CredentialFile); err != nil {
		return nil, ErrInvalid
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxConnsPerHost: 2, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second,
		DisableCompression: true,
	}
	return &Client{config: c, http: &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Close releases idle connections. It does not revoke the platform principal.
func (c *Client) Close() { c.http.CloseIdleConnections() }

func readCredential(path string) (string, error) {
	b, err := privateFile(path, 512)
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(b), "\n")
	if !credentialPattern.MatchString(value) {
		return "", ErrInvalid
	}
	return value, nil
}

// Check performs a new authenticated online check each time. Results are
// observations at that decision, not reusable grants or leases. Call immediately
// before the operation and separately enforce its signed profile authorization.
// There is no success cache or offline fallback.
func (c *Client) Check(ctx context.Context) (Identity, error) {
	var answer Identity
	credential, err := readCredential(c.config.CredentialFile)
	if err != nil {
		return answer, ErrUnavailable
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return answer, ErrUnavailable
	}
	nonce := hex.EncodeToString(random[:])
	body, _ := json.Marshal(map[string]string{
		"schema": "testifysec.agent-session-check.request/v1", "purpose": Purpose,
		"tenant_id": c.config.TenantID, "agent_id": c.config.AgentID,
		"repository_id": c.config.RepositoryID, "nonce": nonce, "refresh_credential": credential,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return answer, ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	started := time.Now()
	res, err := c.http.Do(req)
	if err != nil {
		return answer, ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return answer, ErrRefused
	}
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Content-Encoding") != "" {
		return answer, ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 16385))
	if err != nil || len(b) > 16384 {
		return answer, ErrUnavailable
	}
	if err = strictJSON(b, &answer); err != nil {
		return Identity{}, ErrInvalid
	}
	finished := time.Now()
	want := "spiffe://" + c.config.TrustDomain + "/tenant/" + c.config.TenantID + "/agent/" + c.config.AgentID
	d := answer.Delegation
	if answer.Schema != "testifysec.agent-session-check.response/v1" || answer.Purpose != Purpose || !answer.Authenticated || answer.Authorization != "none" || answer.RepositoryScope != "enrollment-repository" || answer.TenantID != c.config.TenantID || answer.AgentID != c.config.AgentID || answer.RepositoryID != c.config.RepositoryID || answer.SPIFFEID != want || answer.Nonce != nonce || answer.CheckedAt.Before(started.Add(-2*time.Second)) || answer.CheckedAt.After(finished.Add(2*time.Second)) || finished.Sub(started) > 5*time.Second || !answer.ExpiresAt.After(finished) || !answer.ExpiresAt.After(answer.CheckedAt) || answer.CheckedAt.Location() != time.UTC || answer.ExpiresAt.Location() != time.UTC || d.Source != "agent-enrollment" || !validID(d.UserID) || !validID(d.IdentityID) || d.HumanPresence != "not-asserted" || len(d.EnrollmentGitoid) == 0 || len(d.EnrollmentGitoid) > 1024 || strings.ContainsAny(d.EnrollmentGitoid, "\r\n\x00") || assurance(d.EnrollmentAAL) < assurance(c.config.MinimumEnrollmentAAL) {
		return Identity{}, ErrInvalid
	}
	return answer, nil
}
