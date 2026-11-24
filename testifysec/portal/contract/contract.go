// Package contract is the portal API conformance suite (api/openapi.yaml). It speaks only
// HTTP, so it runs against this portal in-process or against any other implementation.
// It creates signed profiles: point it at a test deployment, never production.
package contract

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"
)

// T is the subset of testing.TB the suite needs, so a command can run it too.
type T interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Target is an implementation under test. Clients carry each role's credential; Anonymous has none.
type Target struct {
	Base                      string
	Admin, Auditor, Anonymous *http.Client
}

func call(t T, c *http.Client, method, url string, body any, out any) int {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, url, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

type version struct {
	ProfileID      string `json:"profileId"`
	Sequence       uint64 `json:"sequence"`
	PayloadSHA256  string `json:"payloadSha256"`
	EnvelopeSHA256 string `json:"envelopeSha256"`
}

type problem struct {
	Status int    `json:"status"`
	Error  string `json:"error"`
}

// Run is the whole suite.
func Run(t T, tg Target) {
	t.Helper()
	suffix := make([]byte, 4)
	rand.Read(suffix)
	id := "contract-" + hex.EncodeToString(suffix)
	versions := tg.Base + "/api/v1/profiles/" + id + "/versions"
	now := time.Now().UTC().Truncate(time.Second)
	body := map[string]string{"deploymentId": id, "notBefore": now.Format(time.RFC3339),
		"expiresAt": now.Add(time.Hour).Format(time.RFC3339)}

	var p problem
	if code := call(t, tg.Anonymous, "POST", versions, body, &p); code != 401 || p.Error != "unauthenticated" || p.Status != 401 {
		t.Errorf("anonymous create: %d %+v", code, p)
	}
	if code := call(t, tg.Auditor, "POST", versions, body, &p); code != 403 || p.Error != "forbidden" {
		t.Errorf("auditor create: %d %+v", code, p)
	}
	// Otherwise valid, so only the unknown field can make it fail.
	withSequence := map[string]any{"sequence": 1}
	for k, v := range body {
		withSequence[k] = v
	}
	if code := call(t, tg.Admin, "POST", versions, withSequence, &p); code != 400 || p.Error != "invalid-request" {
		t.Errorf("client-chosen sequence accepted: %d", code)
	}
	var first, second version
	if code := call(t, tg.Admin, "POST", versions, body, &first); code != 201 || first.ProfileID != id || first.Sequence < 1 {
		t.Fatalf("create: %d %+v", code, first)
	}
	if code := call(t, tg.Admin, "POST", versions, body, &second); code != 201 || second.Sequence != first.Sequence+1 {
		t.Errorf("sequence must increase by one: %d %+v after %+v", code, second, first)
	}
	var list struct{ Items []version }
	if code := call(t, tg.Auditor, "GET", tg.Base+"/api/v1/profiles", nil, &list); code != 200 ||
		!slices.ContainsFunc(list.Items, func(v version) bool { return v == second }) {
		t.Errorf("list does not show the latest version: %d", code)
	}
	var trust struct {
		SchemaVersion   int      `json:"schemaVersion"`
		PublicKeys      []string `json:"publicKeys"`
		Threshold       int      `json:"threshold"`
		ProfileID       string   `json:"profileId"`
		MinimumSequence uint64   `json:"minimumSequence"`
	}
	code := call(t, tg.Auditor, "GET", fmt.Sprintf("%s/api/v1/profiles/%s/trust", tg.Base, id), nil, &trust)
	if code != 200 || trust.SchemaVersion != 1 || len(trust.PublicKeys) < 1 || trust.Threshold < 1 ||
		trust.Threshold > len(trust.PublicKeys) || trust.ProfileID != id || trust.MinimumSequence != second.Sequence {
		t.Errorf("trust: %d %+v", code, trust)
	}

	var hist struct{ Items []version }
	if code := call(t, tg.Auditor, "GET", versions, nil, &hist); code != 200 || len(hist.Items) != 2 ||
		hist.Items[0] != second || hist.Items[1] != first {
		t.Errorf("history must list both versions, newest first: %d %+v", code, hist.Items)
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/%d/envelope", versions, first.Sequence), nil)
	if resp, err := tg.Auditor.Do(req); err != nil {
		t.Errorf("envelope: %v", err)
	} else {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		sum := sha256.Sum256(raw)
		if resp.StatusCode != 200 || hex.EncodeToString(sum[:]) != first.EnvelopeSHA256 {
			t.Errorf("envelope must be the signed bytes: %d", resp.StatusCode)
		}
	}
	assignment := tg.Base + "/api/v1/deployments/" + id + "/assignment"
	if code := call(t, tg.Admin, "PUT", assignment, map[string]any{"profileId": id, "sequence": second.Sequence}, nil); code != 200 {
		t.Errorf("assign: %d", code)
	}
	if code := call(t, tg.Admin, "PUT", assignment, map[string]any{"profileId": id, "sequence": first.Sequence}, &p); code != 409 || p.Error != "rollback" {
		t.Errorf("re-pinning an older version must be refused: %d %+v", code, p)
	}
	var d struct{ APIBase string }
	if code := call(t, tg.Anonymous, "GET", tg.Base+"/.well-known/badger-portal", nil, &d); code != 200 || d.APIBase != "/api/v1" {
		t.Errorf("discovery: %d %+v", code, d)
	}
}
