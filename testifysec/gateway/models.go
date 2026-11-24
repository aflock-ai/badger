package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// The unsigned profile (2026-11-03 decision: keep profiles, unsigned for now): the
// administrator's profile as a plain JSON file, read by the gateway itself with no admission
// executable. Its bytes are pinned by profileDigest, so the file cannot change under a running
// gateway, but no signature says who wrote it: whoever can write the gateway's protected config can
// write this. It carries the gateway's accredited marking, the markings of the connectors the
// session may use, its validity window and the models a session may choose among.
const unsignedProfileSchema = "testifysec.hardened-opencode.profile.unsigned/v1"

// ModelEntry is one model the profile allows: the exact ID sent to the provider, the name the
// managed UI shows, and optionally the model's own context and output, which can only lower what
// the managed agent asks for.
type ModelEntry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Context *int   `json:"context,omitempty"`
	Output  *int   `json:"output,omitempty"`
}

type unsignedConnector struct {
	Name           string `json:"name"`
	Classification string `json:"classification"`
}

type unsignedProfile struct {
	Schema    string `json:"schema"`
	TenantID  string `json:"tenantId"`
	NotBefore string `json:"notBefore"`
	ExpiresAt string `json:"expiresAt"`
	Gateway   struct {
		Classification string `json:"classification"`
	} `json:"gateway"`
	Connectors []unsignedConnector `json:"connectors"`
	Models     []ModelEntry        `json:"models"`
}

const (
	maxModels    = 32
	maxModelSize = 1 << 24
)

var (
	// reModelID is a model ID the gateway admits from a profile or writes to an audit record. It is
	// also a managed model key, so no slash (the provider/model separator) and no whitespace.
	reModelID       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	reModelName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .,:_()/+-]{0,63}$`)
	reConnectorName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// readUnsignedProfile reads the unsigned profile at c.ProfileFile, checks it is the one
// c.ProfileDigest pins, for c.Tenant, valid at now, and well formed, and returns what a request may
// rely on and the models it allows.
func readUnsignedProfile(c Config, now time.Time) (admitted, []ModelEntry, error) {
	raw, err := privateFile(c.ProfileFile, 32768)
	if err != nil {
		return admitted{}, nil, errors.New("unsigned profile unavailable")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != c.ProfileDigest {
		return admitted{}, nil, errors.New("unsigned profile does not match its pinned digest")
	}
	var p unsignedProfile
	if err = strictTyped(raw, &p, nil); err != nil {
		return admitted{}, nil, errors.New("invalid unsigned profile")
	}
	start, startErr := time.Parse(time.RFC3339, p.NotBefore)
	end, endErr := time.Parse(time.RFC3339, p.ExpiresAt)
	if p.Schema != unsignedProfileSchema || p.TenantID != c.Tenant || startErr != nil || endErr != nil ||
		!end.After(start) || now.Before(start) || !now.Before(end) {
		return admitted{}, nil, errors.New("unsigned profile binding or validity refused")
	}
	accredited, err := marking.Parse(p.Gateway.Classification)
	if err != nil || len(p.Connectors) > 16 {
		return admitted{}, nil, errors.New("invalid unsigned profile")
	}
	connectors := make([]marking.Marking, 0, len(p.Connectors))
	names := map[string]bool{}
	for _, connector := range p.Connectors {
		m, err := marking.Parse(connector.Classification)
		if err != nil || !reConnectorName.MatchString(connector.Name) || names[connector.Name] {
			return admitted{}, nil, errors.New("invalid unsigned profile connector")
		}
		names[connector.Name] = true
		connectors = append(connectors, m)
	}
	if err = validModels(p.Models, c.Model); err != nil {
		return admitted{}, nil, err
	}
	return admitted{expires: end, accredited: &accredited, connectors: connectors}, p.Models, nil
}

// validModels: 1 to 32 distinct well-formed models, one of them the configured default.
func validModels(models []ModelEntry, model string) error {
	if len(models) == 0 || len(models) > maxModels {
		return errors.New("unsigned profile needs 1 to 32 models")
	}
	ids := map[string]bool{}
	for _, m := range models {
		if !reModelID.MatchString(m.ID) || !reModelName.MatchString(m.Name) || ids[m.ID] ||
			m.Context != nil && (*m.Context < 1 || *m.Context > maxModelSize) || m.Output != nil && (*m.Output < 1 || *m.Output > maxModelSize) {
			return errors.New("invalid unsigned profile model")
		}
		ids[m.ID] = true
	}
	if !ids[model] {
		return errors.New("the configured model is not in the unsigned profile's models")
	}
	return nil
}

// unsignedProfileConfiguration: an absolute clean path and no admission executable, under v3 only
// (profileVersionConfiguration).
func unsignedProfileConfiguration(c Config) error {
	if !filepath.IsAbs(c.ProfileFile) || filepath.Clean(c.ProfileFile) != c.ProfileFile {
		return errors.New("absolute clean unsigned profile path required")
	}
	if c.AdmissionExecutable != "" || c.AdmissionSHA256 != "" {
		return errors.New("an unsigned profile takes no admission executable")
	}
	return nil
}

// allowed reports whether a request may name model: one of the profile's models, or with no
// profile allowlist exactly the configured model (the behavior before allowlists).
func (g *Gateway) allowed(model string) bool {
	if g.models == nil {
		return model == g.config.Model
	}
	for _, m := range g.models {
		if m.ID == model {
			return true
		}
	}
	return false
}

// listModels serves the profile's allowlist and default, written by the gateway: the provider is
// not asked and nothing from the request is used. With no profile allowlist it is a fixed 404, and
// the managed agent keeps its compiled model.
func (g *Gateway) listModels(w http.ResponseWriter) (string, int) {
	if g.models == nil {
		http.Error(w, "models unavailable", http.StatusNotFound)
		return "models-unavailable", http.StatusNotFound
	}
	b, err := json.Marshal(struct {
		Default string       `json:"default"`
		Models  []ModelEntry `json:"models"`
	}{g.config.Model, g.models})
	if err != nil {
		http.Error(w, "models unavailable", http.StatusNotFound)
		return "models-unavailable", http.StatusNotFound
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
	return "models-served", http.StatusOK
}

// profileSignature is what the audit says about the profile behind every request.
func profileSignature(c Config) string {
	switch {
	case c.ProfileFile != "":
		return "unsigned"
	case c.SignedProfileFile != "":
		return "signed"
	default:
		return "none"
	}
}

// startLine is what the gateway logs about its profile at start.
func startLine(g *Gateway) string {
	ids := []string{g.config.Model}
	if g.models != nil {
		ids = ids[:0]
		for _, m := range g.models {
			ids = append(ids, m.ID)
		}
	}
	return fmt.Sprintf("profile=%s sha256=%s default=%s models=%s", profileSignature(g.config), g.config.ProfileDigest, g.config.Model, strings.Join(ids, ","))
}
