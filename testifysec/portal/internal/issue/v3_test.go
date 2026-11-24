package issue_test

// Profile v3: the portal signs what native admission v3 accepts and what gateway v3 then reads.
//   - signature: verifyNativeType, as for v1, with the v3 payload type;
//   - payload: admitV3, a port of admitProfileV3 in testifysec/managed/profile-v3.ts, which checks
//     gateway and connectors and then applies the unchanged v1 rules to the payload without them;
//   - output: admissionV3 prints what admission-cli.ts prints, and gatewayV3 reads it as
//     decodeProfileV3 in testifysec/gateway/profile_v3.go does, with the gateway ceiling that
//     packages/cli/src/managed-connectors.ts and gateway v3 both enforce.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
	"github.com/aflock-ai/badger/testifysec/portal/internal/issue"
	"github.com/aflock-ai/badger/testifysec/portal/internal/profile"
)

func connectorsFixture() []profile.Connector {
	ca, notice := "/etc/badger/enclave-ca.pem", "Test data only."
	return []profile.Connector{
		{Name: "jira", BinarySHA256: strings.Repeat("a", 64), BaseURL: "https://jira.example.invalid", TokenPath: "/run/badger/tokens/jira.token",
			CAPath: &ca, Classification: "CONFIDENTIAL", Notice: &notice,
			Flags: map[string]string{"marking-field": "customfield_10001"}, Permissions: map[string]string{"jira_*": "allow", "jira_add_comment": "ask"}},
		// A bridged connector: the pinned binary is the bridge, the URL the connector pod's stream.
		{Name: "gitlab", BinarySHA256: strings.Repeat("b", 64), BaseURL: "https://conngw.example.invalid:8443/connectors/gitlab",
			TokenPath: "/var/run/secrets/tokens/workspace", Writes: true, Classification: "UNCLASSIFIED",
			Flags: map[string]string{"auth": "bearer"}, Permissions: map[string]string{}},
		// A plugin outside the catalog, served by the connector pod under its own name.
		{Name: "servicenow-1", BinarySHA256: strings.Repeat("c", 64), BaseURL: "https://conngw.example.invalid:8443/connectors/servicenow-1",
			TokenPath: "/var/run/secrets/tokens/workspace", CAPath: &ca, Classification: "UNCLASSIFIED",
			Flags: map[string]string{"region": "us-1"}, Permissions: map[string]string{"servicenow-1_*": "ask"}},
	}
}

func v3Request(from, to time.Duration) issue.Request {
	r := window(from, to)
	r.SchemaVersion = 3
	r.Gateway = &profile.Gateway{Classification: "SECRET"}
	r.Connectors = connectorsFixture()
	return r
}

// v3Catalog is profile-v3.ts catalog: connector -> flag -> allowed values (nil: any flag value).
var v3Catalog = map[string]map[string][]string{
	"jira":       {"marking-field": nil, "marking-label-prefix": nil},
	"confluence": {"label-prefix": nil},
	"gitlab":     {"auth": {"private-token", "bearer"}, "marking-prefix": nil},
}

var connectorKeys = []string{"name", "binarySha256", "baseUrl", "tokenPath", "caPath", "writes", "classification", "flags", "permissions"}

// connectorShape is profile-v3.ts record() for one entry: these keys, notice optional.
func connectorShape(raw json.RawMessage) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return errors.New("invalid-schema")
	}
	keys := connectorKeys
	if _, ok := probe["notice"]; ok {
		keys = append(append([]string(nil), keys...), "notice")
	}
	return exactKeys(raw, keys...)
}

// admitV3 is admitProfileV3 with its reason strings.
func admitV3(payload []byte, tr trust, now time.Time) error {
	if err := exactKeys(payload, "schemaVersion", "profileId", "tenantId", "deploymentId", "sequence", "notBefore", "expiresAt",
		"controls", "gateway", "connectors"); err != nil {
		return err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil || string(top["schemaVersion"]) != "3" {
		return errors.New("unsupported-profile-version")
	}
	if err := exactKeys(top["gateway"], "classification"); err != nil {
		return err
	}
	var gw profile.Gateway
	if json.Unmarshal(top["gateway"], &gw) != nil {
		return errors.New("invalid-classification")
	}
	if _, err := marking.Parse(gw.Classification); err != nil {
		return errors.New("invalid-classification")
	}
	var entries []json.RawMessage
	if json.Unmarshal(top["connectors"], &entries) != nil || entries == nil || len(entries) > 16 {
		return errors.New("invalid-schema")
	}
	names := map[string]bool{}
	for _, raw := range entries {
		if err := connectorShape(raw); err != nil {
			return err
		}
		var c struct {
			Name, BinarySHA256, BaseURL, TokenPath, Classification string
			CAPath, Notice                                         *string
			Writes                                                 bool
			Flags, Permissions                                     map[string]string
		}
		if json.Unmarshal(raw, &c) != nil || c.Flags == nil || c.Permissions == nil {
			return errors.New("invalid-schema")
		}
		// A name outside the catalog is a plugin: the connector pod's name rule, and its flag rule
		// (internal/launch FlagName, not Reserved) without notice.
		if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(c.Name) {
			return errors.New("unknown-connector")
		}
		flags, listed := v3Catalog[c.Name]
		if !listed {
			flags = map[string][]string{}
			for k := range c.Flags {
				if regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(k) && !strings.Contains(
					",base-url,token-file,classification,ca-file,enable-writes,insecure-loopback-http,manifest,notice,", ","+k+",") {
					flags[k] = nil
				}
			}
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.BinarySHA256) {
			return errors.New("invalid-connector-pin")
		}
		u, err := url.Parse(c.BaseURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(c.BaseURL, "?# \\") {
			return errors.New("invalid-connector-url")
		}
		for _, p := range []*string{&c.TokenPath, c.CAPath} {
			if p != nil && (!strings.HasPrefix(*p, "/") || strings.HasSuffix(*p, "/") || strings.Contains(*p, "/../") || strings.Contains(*p, "//")) {
				return errors.New("invalid-connector-path")
			}
		}
		if _, err := marking.Parse(c.Classification); err != nil {
			return errors.New("invalid-classification")
		}
		for k, v := range c.Flags {
			values, ok := flags[k]
			if !ok || (values != nil && !strings.Contains(","+strings.Join(values, ",")+",", ","+v+",")) {
				return errors.New("invalid-connector-flag")
			}
		}
		for k, v := range c.Permissions {
			if !strings.HasPrefix(k, c.Name+"_") || !regexp.MustCompile(`^[a-z0-9_]*\*?$`).MatchString(k[len(c.Name)+1:]) ||
				(v != "allow" && v != "ask" && v != "deny") {
				return errors.New("invalid-connector-permission")
			}
		}
		if names[c.Name] {
			return errors.New("duplicate-connector")
		}
		names[c.Name] = true
	}
	// The unchanged v1 rules on the payload without gateway and connectors, raw values kept.
	delete(top, "gateway")
	delete(top, "connectors")
	top["schemaVersion"] = json.RawMessage("1")
	common, err := json.Marshal(top)
	if err != nil {
		return err
	}
	return admitV1(common, tr, now)
}

// admissionV3 is the line admission-cli.ts prints for an admitted v3 payload.
func admissionV3(payload []byte, envelopeSHA, payloadSHA string, keyIDs []string) []byte {
	var p struct {
		ProfileID    string          `json:"profileId"`
		TenantID     string          `json:"tenantId"`
		DeploymentID string          `json:"deploymentId"`
		Sequence     uint64          `json:"sequence"`
		NotBefore    string          `json:"notBefore"`
		ExpiresAt    string          `json:"expiresAt"`
		Gateway      json.RawMessage `json:"gateway"`
		Connectors   json.RawMessage `json:"connectors"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		panic(err)
	}
	out, err := json.Marshal(map[string]any{"schemaVersion": 3, "admitted": true, "scope": "profile-admission-only", "profile": p,
		"envelopeSha256": envelopeSHA, "payloadSha256": payloadSHA, "signerKeyIds": keyIDs,
		"trustSha256": strings.Repeat("d", 64), "nativeSha256": strings.Repeat("e", 64)})
	if err != nil {
		panic(err)
	}
	return append(out, '\n')
}

// gatewayV3 reads an admission line as gateway v3 does: at most 16384 bytes (admissionBuffer), the
// exact fields of profileAdmissionV3 (caPath may be null, notice may be absent but not null), every
// marking parsed, and no connector above the gateway's accreditation.
func gatewayV3(out []byte) (marking.Marking, []marking.Marking, error) {
	var none marking.Marking
	if len(out) > 16384 {
		return none, nil, errors.New("admission output over the gateway's buffer")
	}
	out = bytes.TrimSuffix(out, []byte("\n"))
	if err := exactKeys(out, "schemaVersion", "admitted", "scope", "profile", "envelopeSha256", "payloadSha256", "signerKeyIds",
		"trustSha256", "nativeSha256"); err != nil {
		return none, nil, err
	}
	var result struct{ Profile json.RawMessage }
	if err := json.Unmarshal(out, &result); err != nil {
		return none, nil, err
	}
	if err := exactKeys(result.Profile, "profileId", "tenantId", "deploymentId", "sequence", "notBefore", "expiresAt", "gateway", "connectors"); err != nil {
		return none, nil, err
	}
	var p struct {
		Gateway    profile.Gateway
		Connectors []json.RawMessage
	}
	if err := json.Unmarshal(result.Profile, &p); err != nil || p.Connectors == nil {
		return none, nil, errors.New("profile v3 admission refused")
	}
	accredited, err := marking.Parse(p.Gateway.Classification)
	if err != nil {
		return none, nil, err
	}
	var connectors []marking.Marking
	for _, raw := range p.Connectors {
		var fields map[string]json.RawMessage
		if err := connectorShape(raw); err != nil || json.Unmarshal(raw, &fields) != nil || string(fields["notice"]) == "null" {
			return none, nil, errors.New("profile v3 admission refused")
		}
		var c profile.Connector
		if err := json.Unmarshal(raw, &c); err != nil {
			return none, nil, err
		}
		m, err := marking.Parse(c.Classification)
		if err != nil || !marking.Dominates(accredited, m) {
			return none, nil, errors.New("connector above the gateway's accreditation")
		}
		connectors = append(connectors, m)
	}
	return accredited, connectors, nil
}

func TestAdmissionAcceptsPortalProfileV3(t *testing.T) {
	for _, n := range []int{1, 2} {
		iss, audit := newIssuer(t, n)
		v, err := iss.Issue("CN=Admin One", "admin", v3Request(-time.Hour, 24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		tr := trustFor(iss, 10)
		if _, _, _, err := verifyNative(v.Envelope, tr); err == nil {
			t.Fatal("a v3 envelope verified as v1")
		}
		payload, payloadSHA, ids, err := verifyNativeType(v.Envelope, tr, profile.PayloadTypeV3)
		if err != nil {
			t.Fatalf("native verifier refused a portal v3 envelope: %v", err)
		}
		if err = admitV3(payload, tr, time.Now()); err != nil {
			t.Fatalf("admission v3 refused a portal payload: %v", err)
		}
		envSum := sha256.Sum256(v.Envelope)
		if payloadSHA != v.PayloadSHA256 || hex.EncodeToString(envSum[:]) != v.EnvelopeSHA256 || len(ids) != n {
			t.Fatal("digest or signer binding differs from what admission reports")
		}
		accredited, connectors, err := gatewayV3(admissionV3(payload, v.EnvelopeSHA256, payloadSHA, ids))
		if err != nil || marking.Banner(accredited) != "SECRET" || len(connectors) != 3 ||
			marking.Banner(connectors[0]) != "CONFIDENTIAL" || marking.Banner(connectors[1]) != "UNCLASSIFIED" {
			t.Fatalf("gateway v3 refused the admission of a portal profile: %v", err)
		}
		if got := iss.Trust(v)["schemaVersion"]; got != 3 {
			t.Fatalf("trust for a v3 version has schemaVersion %v", got)
		}
		if len(audit.records) != 1 || audit.records[0].Action != "profile.sign" {
			t.Fatalf("audit %+v", audit.records)
		}
	}
}

// Every field of the signed payload is covered: changing any one, and keeping the signatures, is refused.
func TestTamperedV3FieldRefused(t *testing.T) {
	iss, _ := newIssuer(t, 1)
	v, err := iss.Issue("CN=Admin One", "admin", v3Request(-time.Hour, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	tr := trustFor(iss, 10)
	var env struct {
		PayloadType string          `json:"payloadType"`
		Payload     []byte          `json:"payload"`
		Signatures  json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(v.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	rewrap := func(p profile.V3) []byte {
		payload, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		env.Payload = payload
		raw, _ := json.Marshal(env)
		return raw
	}
	decode := func() profile.V3 {
		var p profile.V3
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	original := append([]byte(nil), env.Payload...)
	// The re-encoding alone changes nothing, so each refusal below is the edit's.
	if _, _, _, err := verifyNativeType(rewrap(decode()), tr, profile.PayloadTypeV3); err != nil {
		t.Fatal("re-encoded payload no longer verifies:", err)
	}
	str := func(s string) *string { return &s }
	edits := map[string]func(*profile.V3){
		"schemaVersion":  func(p *profile.V3) { p.SchemaVersion = 1 },
		"profileId":      func(p *profile.V3) { p.ProfileID += "x" },
		"tenantId":       func(p *profile.V3) { p.TenantID += "x" },
		"deploymentId":   func(p *profile.V3) { p.DeploymentID += "x" },
		"sequence":       func(p *profile.V3) { p.Sequence++ },
		"notBefore":      func(p *profile.V3) { p.NotBefore = "2020-01-01T00:00:00Z" },
		"expiresAt":      func(p *profile.V3) { p.ExpiresAt = "2099-01-01T00:00:00Z" },
		"controls.rpd":   func(p *profile.V3) { p.Controls.RuntimePackageDownloads = true },
		"controls.exec":  func(p *profile.V3) { p.Controls.Execution = "local" },
		"controls.audit": func(p *profile.V3) { p.Controls.Audit = "optional" },
		"gateway":        func(p *profile.V3) { p.Gateway.Classification = "TOP SECRET" },
		"name":           func(p *profile.V3) { p.Connectors[0].Name = "confluence" },
		"binarySha256":   func(p *profile.V3) { p.Connectors[0].BinarySHA256 = strings.Repeat("c", 64) },
		"baseUrl":        func(p *profile.V3) { p.Connectors[0].BaseURL = "https://elsewhere.example.invalid" },
		"tokenPath":      func(p *profile.V3) { p.Connectors[0].TokenPath = "/run/badger/tokens/other" },
		"caPath":         func(p *profile.V3) { p.Connectors[0].CAPath = nil },
		"caPath-set":     func(p *profile.V3) { p.Connectors[1].CAPath = str("/etc/ca.pem") },
		"writes":         func(p *profile.V3) { p.Connectors[0].Writes = true },
		"classification": func(p *profile.V3) { p.Connectors[1].Classification = "SECRET" },
		"notice":         func(p *profile.V3) { p.Connectors[0].Notice = nil },
		"flag-value":     func(p *profile.V3) { p.Connectors[1].Flags["auth"] = "private-token" },
		"flag-added":     func(p *profile.V3) { p.Connectors[0].Flags["marking-label-prefix"] = "m-" },
		"permission":     func(p *profile.V3) { p.Connectors[0].Permissions["jira_add_comment"] = "allow" },
		"connector-gone": func(p *profile.V3) { p.Connectors = p.Connectors[:1] },
		"connector-new":  func(p *profile.V3) { p.Connectors = append(p.Connectors, p.Connectors[0]) },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			env.Payload = original
			p := decode()
			edit(&p)
			raw := rewrap(p)
			if bytes.Equal(env.Payload, original) {
				t.Fatal("edit changed nothing")
			}
			if _, _, _, err := verifyNativeType(raw, tr, profile.PayloadTypeV3); err == nil {
				t.Fatal("tampered v3 payload verified")
			}
		})
	}
	env.Payload = original
	downgraded := bytes.Replace(rewrap(decode()), []byte(profile.PayloadTypeV3), []byte(profile.PayloadType), 1)
	if _, _, _, err := verifyNativeType(downgraded, tr, profile.PayloadType); err == nil {
		t.Fatal("a v3 signature verified under the v1 payload type")
	}
}

// The issuer refuses at authoring what admission or the gateway would refuse later, and audits nothing.
func TestIssuerRefusesInvalidV3(t *testing.T) {
	iss, audit := newIssuer(t, 1)
	str := func(s string) *string { return &s }
	cases := map[string]func(*issue.Request){
		"version-2":           func(r *issue.Request) { r.SchemaVersion = 2 },
		"version-4":           func(r *issue.Request) { r.SchemaVersion = 4 },
		"v1-with-connectors":  func(r *issue.Request) { r.SchemaVersion = 0 },
		"v1-with-gateway":     func(r *issue.Request) { r.SchemaVersion = 1; r.Connectors = nil },
		"no-gateway":          func(r *issue.Request) { r.Gateway = nil },
		"no-connectors":       func(r *issue.Request) { r.Connectors = nil },
		"gateway-marking":     func(r *issue.Request) { r.Gateway.Classification = "SECRETISH" },
		"unknown-connector":   func(r *issue.Request) { r.Connectors[0].Name = "wiki_1" },
		"duplicate-connector": func(r *issue.Request) { r.Connectors[1] = r.Connectors[0] },
		"pin-short":           func(r *issue.Request) { r.Connectors[0].BinarySHA256 = "abc" },
		"pin-uppercase":       func(r *issue.Request) { r.Connectors[0].BinarySHA256 = strings.Repeat("A", 64) },
		"url-http":            func(r *issue.Request) { r.Connectors[0].BaseURL = "http://jira.example.invalid" },
		"url-query":           func(r *issue.Request) { r.Connectors[0].BaseURL = "https://jira.example.invalid/?a=b" },
		"url-empty-query":     func(r *issue.Request) { r.Connectors[0].BaseURL = "https://jira.example.invalid/?" },
		"url-fragment":        func(r *issue.Request) { r.Connectors[0].BaseURL = "https://jira.example.invalid/#x" },
		"url-credentials":     func(r *issue.Request) { r.Connectors[0].BaseURL = "https://u:p@jira.example.invalid" },
		"url-no-host":         func(r *issue.Request) { r.Connectors[0].BaseURL = "https:jira.example.invalid" },
		"url-space":           func(r *issue.Request) { r.Connectors[0].BaseURL = "https://jira.example.invalid/a b" },
		"url-unicode-host":    func(r *issue.Request) { r.Connectors[0].BaseURL = "https://jïra.example.invalid" },
		"url-port":            func(r *issue.Request) { r.Connectors[0].BaseURL = "https://jira.example.invalid:70000" },
		"url-ipv4-range":      func(r *issue.Request) { r.Connectors[0].BaseURL = "https://999.1.1.1" },
		"url-numeric-label":   func(r *issue.Request) { r.Connectors[0].BaseURL = "https://jira.123" },
		"url-bracketed-name":  func(r *issue.Request) { r.Connectors[0].BaseURL = "https://[jira.example.invalid]" },
		"url-bracketed-ipv4":  func(r *issue.Request) { r.Connectors[0].BaseURL = "https://[192.0.2.10]:443" },
		"url-punycode":        func(r *issue.Request) { r.Connectors[0].BaseURL = "https://xn--a.example" },
		"url-escaped-host":    func(r *issue.Request) { r.Connectors[0].BaseURL = "https://%6Aira.example.invalid" },
		"token-relative":      func(r *issue.Request) { r.Connectors[0].TokenPath = "run/token" },
		"token-dotdot":        func(r *issue.Request) { r.Connectors[0].TokenPath = "/run/../token" },
		"token-trailing":      func(r *issue.Request) { r.Connectors[0].TokenPath = "/run/token/" },
		"ca-control":          func(r *issue.Request) { r.Connectors[0].CAPath = str("/etc/ca\n.pem") },
		"flag-unknown":        func(r *issue.Request) { r.Connectors[0].Flags["auth"] = "bearer" },
		"flag-value-set":      func(r *issue.Request) { r.Connectors[1].Flags["auth"] = "basic" },
		"flag-value-grammar":  func(r *issue.Request) { r.Connectors[0].Flags["marking-field"] = "-x" },
		"flags-missing":       func(r *issue.Request) { r.Connectors[0].Flags = nil },
		"permissions-missing": func(r *issue.Request) { r.Connectors[1].Permissions = nil },
		"permission-foreign":  func(r *issue.Request) { r.Connectors[0].Permissions["gitlab_push"] = "allow" },
		"permission-effect":   func(r *issue.Request) { r.Connectors[0].Permissions["jira_x"] = "always" },
		"permission-grammar":  func(r *issue.Request) { r.Connectors[0].Permissions["jira_X"] = "allow" },
		"notice-empty":        func(r *issue.Request) { r.Connectors[0].Notice = str("") },
		"notice-grammar":      func(r *issue.Request) { r.Connectors[0].Notice = str("<b>bold</b>") },
		"connector-marking":   func(r *issue.Request) { r.Connectors[0].Classification = "CONFIDENTIALISH" },
		"above-gateway":       func(r *issue.Request) { r.Connectors[0].Classification = "TOP SECRET" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			r := v3Request(-time.Hour, time.Hour)
			edit(&r)
			var invalid issue.Invalid
			if _, err := iss.Issue("CN=Admin One", "admin", r); !errors.As(err, &invalid) {
				t.Fatalf("want Invalid, got %v", err)
			}
		})
	}
	if len(audit.records) != 0 {
		t.Fatalf("refused requests were audited as signatures: %d records", len(audit.records))
	}
}

// The issuer refuses a profile whose admission line would overflow the gateway's 16384-byte
// buffer, and signs anything up to that bound.
func TestV3SizeBound(t *testing.T) {
	iss, _ := newIssuer(t, 2)
	tr := trustFor(iss, 10)
	sized := func(n int) issue.Request {
		r := v3Request(-time.Hour, time.Hour)
		for i := range n {
			r.Connectors[0].Permissions[fmt.Sprintf("jira_tool_%04d", i)] = "deny"
		}
		return r
	}
	accepted, refused, acceptedLen := 0, 2000, 0
	if _, err := iss.Issue("CN=Admin One", "admin", sized(refused)); err == nil {
		t.Fatal("an oversized profile was signed")
	}
	for refused-accepted > 1 {
		mid := (accepted + refused) / 2
		v, err := iss.Issue("CN=Admin One", "admin", sized(mid))
		var invalid issue.Invalid
		switch {
		case err == nil:
			payload, payloadSHA, ids, verr := verifyNativeType(v.Envelope, tr, profile.PayloadTypeV3)
			if verr != nil || len(v.Envelope) > issue.MaxEnvelope {
				t.Fatal(verr)
			}
			line := admissionV3(payload, v.EnvelopeSHA256, payloadSHA, ids)
			if _, _, gerr := gatewayV3(line); gerr != nil {
				t.Fatalf("signed with %d permissions, which the gateway refuses: %v", mid, gerr)
			}
			accepted, acceptedLen = mid, len(line)
		case errors.As(err, &invalid):
			refused = mid
		default:
			t.Fatal(err)
		}
	}
	// The bound is the buffer, not a guess well under it: the largest signed profile's line is
	// within one permission entry (27 bytes) of 16384.
	if acceptedLen <= 16384-27 {
		t.Fatalf("largest signed profile (%d permissions) prints only %d bytes", accepted, acceptedLen)
	}
}

func TestV1IssuanceUnchanged(t *testing.T) {
	iss, _ := newIssuer(t, 1)
	explicit := window(-time.Hour, time.Hour)
	explicit.SchemaVersion = 1
	for _, r := range []issue.Request{window(-time.Hour, time.Hour), explicit} {
		v, err := iss.Issue("CN=Admin One", "admin", r)
		if err != nil {
			t.Fatal(err)
		}
		tr := trustFor(iss, 10)
		payload, _, _, err := verifyNative(v.Envelope, tr)
		if err != nil || admitV1(payload, tr, time.Now()) != nil {
			t.Fatalf("v1 envelope: %v", err)
		}
		if got := iss.Trust(v)["schemaVersion"]; got != 1 {
			t.Fatalf("trust for a v1 version has schemaVersion %v", got)
		}
	}
}
