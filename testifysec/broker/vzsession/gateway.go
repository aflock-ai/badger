package vzsession

import (
	"encoding/json"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aflock-ai/badger/testifysec/platform"
)

// gatewayTokenFD is the descriptor the gateway reads its provider token from: the first of
// exec.Cmd.ExtraFiles.
const gatewayTokenFD = 3

type gatewayTemplate struct {
	Schema      string `json:"schema"`
	ProviderURL string `json:"providerURL"`
	Protocol    string `json:"protocol"`
	// BrokerSignIn is how the session gets the provider token: device sign-in at the edge, held in
	// memory and handed to the gateway over a pipe. There is no token file.
	BrokerSignIn        *brokerSignIn `json:"brokerSignIn"`
	CollectorURL        string        `json:"collectorURL"`
	CollectorTokenFile  string        `json:"collectorTokenFile"`
	Model               string        `json:"model"`
	MaxRecords          int           `json:"maxRecords"`
	MaxOfflineSeconds   int           `json:"maxOfflineSeconds"`
	TimeoutSeconds      int           `json:"timeoutSeconds"`
	DevelopmentLoopback bool          `json:"developmentLoopback"`
}

func (t gatewayTemplate) validate() error {
	if !t.validBounds() {
		return refused("gateway_template")
	}
	// The current compiled managed worker fixes both this model identifier and
	// transport. Refuse unsupported assignments before preparing or booting a VM.
	// Real provider routing requires a coordinated worker/gateway contract.
	if t.Protocol != "chat-completions" || t.Model != "approved" {
		return refused("worker_route_unsupported")
	}
	if !endpoint(t.ProviderURL, "/v1/chat/completions", t.DevelopmentLoopback) || !endpoint(t.CollectorURL, "/v1/logs", t.DevelopmentLoopback) {
		return refused("gateway_endpoint")
	}
	if t.CollectorTokenFile != "" && !absolute(t.CollectorTokenFile) {
		return refused("gateway_token_path")
	}
	if t.BrokerSignIn == nil {
		return refused("broker_signin_required")
	}
	if err := t.BrokerSignIn.validate(); err != nil {
		return err
	}
	// The provider is the broker behind the same edge the person signs in at.
	if t.ProviderURL != t.BrokerSignIn.base()+"/v1/chat/completions" {
		return refused("broker_signin_provider")
	}
	return nil
}

func (t gatewayTemplate) validBounds() bool {
	return t.Schema == "testifysec.aflock.vz-gateway-template/v1" && len(t.Model) > 0 && len(t.Model) <= 128 && !strings.ContainsAny(t.Model, "\r\n\x00") && t.MaxRecords >= 2 && t.MaxRecords <= 10000 && t.MaxOfflineSeconds >= 1 && t.MaxOfflineSeconds <= 86400 && t.TimeoutSeconds >= 1 && t.TimeoutSeconds <= 600
}

// rePathPrefix is a clean path prefix: segments of letters, digits, '-' and '_', no dots.
var rePathPrefix = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)*$`)

func endpoint(raw, path string, dev bool) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		!strings.HasSuffix(u.Path, path) || !rePathPrefix.MatchString(strings.TrimSuffix(u.Path, path)) {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return dev && u.Scheme == "http" && ip != nil && ip.IsLoopback()
}

func (c configuration) gatewayConfig(session, dir, audit string, identity platformsession.Identity) ([]byte, error) {
	t := c.template
	cfg := map[string]any{
		"schema": "testifysec.hardened-opencode.gateway/v2",
		"socket": filepath.Join(dir, "gateway.sock"), "spool": filepath.Join(audit, "spool"),
		"providerURL": t.ProviderURL, "protocol": t.Protocol, "providerTokenFd": gatewayTokenFD,
		"collectorURL": t.CollectorURL, "collectorTokenFile": t.CollectorTokenFile, "model": t.Model,
		"tenant": identity.TenantID, "agent": identity.SPIFFEID, "session": session,
		"profileDigest": c.backend.ProfileSHA256, "maxRecords": t.MaxRecords, "maxOfflineSeconds": t.MaxOfflineSeconds,
		"timeoutSeconds": t.TimeoutSeconds, "developmentLoopback": t.DevelopmentLoopback,
		"platformConfigFile": c.assignment.PlatformConfigFile, "signedProfileFile": filepath.Join(dir, "profile.dsse.json"),
		"admissionExecutable": c.backend.AdmissionExecutable, "admissionSha256": c.backend.AdmissionSHA256,
		"backend": map[string]string{"kind": "darwin-vz/v1", "manifestSha256": c.backend.ManifestSHA256},
	}
	if t.BrokerSignIn.EdgeCertSHA256 != "" {
		cfg["providerCertSha256"] = t.BrokerSignIn.EdgeCertSHA256
	}
	return json.Marshal(cfg)
}
