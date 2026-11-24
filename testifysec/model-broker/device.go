package broker

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Device sign-in: formal/BadgerBroker/DeviceTokens.lean. A person the edge has signed in (with
// whatever identity provider the edge uses) opens /device/authorize on the edge listener, which
// only the edge can reach, and approves a device. The broker redirects the browser to the device's
// loopback listener with a one-time code bound to the person (W4: the edge-verified principal
// header), the device's PKCE challenge and its port. The device redeems the code with its verifier
// on the internal listener and gets a device token in the "dev-" name space. Codes and pending
// consents live in memory only: a restart forgets them, and the person signs in again.

const (
	deviceCodeTTL    = 120 * time.Second
	deviceConsentTTL = 300 * time.Second
	// maxPendingDevice bounds outstanding consents and codes each, so the maps cannot grow without limit.
	maxPendingDevice = 256
)

var (
	reChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	reVerifier  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	reOpaque    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	rePort      = regexp.MustCompile(`^[1-9][0-9]{3,4}$`)
	errDevice   = errors.New("device sign-in refused")
)

// deviceRequest is what the device asked for: its PKCE challenge, loopback port, the state it will
// check on the callback, and its stable (non-secret) device id.
type deviceRequest struct {
	challenge, state, device string
	port                     int
}

type deviceConsent struct {
	principal string
	req       deviceRequest
	exp       time.Time
}

// deviceCode is Lean `Code`.
type deviceCode struct {
	principal, challenge, device string
	port                         int
	exp                          time.Time
}

type deviceState struct {
	mu       sync.Mutex
	consents map[string]deviceConsent
	codes    map[string]deviceCode
}

func newDeviceState() *deviceState {
	return &deviceState{consents: map[string]deviceConsent{}, codes: map[string]deviceCode{}}
}

func randomID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// prune drops expired entries. Caller holds d.mu.
func (d *deviceState) prune(now time.Time) {
	for k, c := range d.consents {
		if !now.Before(c.exp) {
			delete(d.consents, k)
		}
	}
	for k, c := range d.codes {
		if !now.Before(c.exp) {
			delete(d.codes, k)
		}
	}
}

// parseDeviceRequest accepts exactly the four parameters, each once, in their strict forms.
func parseDeviceRequest(raw string) (deviceRequest, bool) {
	q, err := url.ParseQuery(raw)
	if err != nil || len(q) != 4 {
		return deviceRequest{}, false
	}
	one := func(k string) string {
		if v := q[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	r := deviceRequest{challenge: one("challenge"), state: one("state"), device: one("device")}
	p := one("port")
	if !reChallenge.MatchString(r.challenge) || !reOpaque.MatchString(r.state) || !reOpaque.MatchString(r.device) || !rePort.MatchString(p) {
		return deviceRequest{}, false
	}
	r.port, _ = strconv.Atoi(p)
	if r.port < 1024 || r.port > 65535 {
		return deviceRequest{}, false
	}
	return r, true
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Approve device</title>
<style>{{.Theme}}</style>
<main class="center"><div class="card"><div class="eyebrow">Badger broker</div><h1>Approve this device?</h1>
<p>Signed in as <code>{{.Principal}}</code>.</p>
<p>A program on your computer asked for a model token in your name. Approve only if you just started a sign-in yourself. Its token works for {{.Hours}} hours or until it signs out.</p>
<form method="post"><input type="hidden" name="nonce" value="{{.Nonce}}"><button type="submit">Approve</button></form>
<p class="muted small" style="margin-top:var(--sp-4)">If you did not start this, close this page.</p></div></main></html>`))

func deviceHeaders(w http.ResponseWriter, port int) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	// form-action must allow the loopback redirect after the form posts, or browsers block it.
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' http://127.0.0.1:"+strconv.Itoa(port))
}

// deviceAuthorize serves /device/authorize on the edge listener. The person is the edge-set
// principal header and nothing else (W4); a request carrying a pipeline payload is refused.
func (b *Broker) deviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if b.hasPipelinePayload(r) {
		failure(w, http.StatusUnauthorized)
		return
	}
	ps := r.Header.Values(b.cfg.Headers.Principal)
	var principal string
	if len(ps) == 1 {
		principal, _ = configuredPrincipal(b.cfg.HumanPrincipals, ps[0])
	}
	if principal == "" {
		failure(w, http.StatusUnauthorized)
		return
	}
	req, ok := parseDeviceRequest(r.URL.RawQuery)
	if !ok {
		failure(w, http.StatusBadRequest)
		return
	}
	deviceHeaders(w, req.port)
	now := b.now()
	d := b.device
	switch r.Method {
	case http.MethodGet:
		nonce, err := randomID()
		if err != nil {
			failure(w, http.StatusServiceUnavailable)
			return
		}
		d.mu.Lock()
		d.prune(now)
		if len(d.consents) >= maxPendingDevice {
			d.mu.Unlock()
			failure(w, http.StatusServiceUnavailable)
			return
		}
		d.consents[nonce] = deviceConsent{principal: principal, req: req, exp: now.Add(deviceConsentTTL)}
		d.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = consentPage.Execute(w, struct {
			Theme            template.CSS
			Principal, Nonce string
			Hours            int
		}{template.CSS(themeCSS), principal, nonce, b.cfg.DeviceTokenTTLHours})
	case http.MethodPost:
		// Fetch metadata: the approval must come from the consent page itself, not another site.
		if r.Header.Get("Sec-Fetch-Site") != "same-origin" {
			failure(w, http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil || len(r.PostForm) != 1 || len(r.PostForm["nonce"]) != 1 {
			failure(w, http.StatusBadRequest)
			return
		}
		nonce := r.PostForm.Get("nonce")
		code, err := randomID()
		if err != nil {
			failure(w, http.StatusServiceUnavailable)
			return
		}
		d.mu.Lock()
		d.prune(now)
		c, found := d.consents[nonce]
		delete(d.consents, nonce)
		if !found || c.principal != principal || c.req != req {
			d.mu.Unlock()
			failure(w, http.StatusForbidden)
			return
		}
		if len(d.codes) >= maxPendingDevice {
			d.mu.Unlock()
			failure(w, http.StatusServiceUnavailable)
			return
		}
		d.codes[code] = deviceCode{principal: principal, challenge: req.challenge, device: req.device, port: req.port,
			exp: now.Add(deviceCodeTTL)}
		d.mu.Unlock()
		// The broker builds the redirect; nothing the caller sent chooses its scheme, host or path.
		loc := "http://127.0.0.1:" + strconv.Itoa(req.port) + "/callback?code=" + code + "&state=" + req.state
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		failure(w, http.StatusMethodNotAllowed)
	}
}

// redeem is Lean `redeem`: the code is removed on every attempt, and succeeds only with the S256
// of its verifier and its port, before it expires.
func (d *deviceState) redeem(code, verifierHash string, port int, now time.Time) (deviceCode, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, found := d.codes[code]
	delete(d.codes, code)
	if !found || subtle.ConstantTimeCompare([]byte(c.challenge), []byte(verifierHash)) != 1 || c.port != port || !now.Before(c.exp) {
		return deviceCode{}, false
	}
	return c, true
}

// deviceName is the device's name in the "dev-" name space: stable per (person, device), so the
// same device signing in again replaces its token.
func deviceName(principal, device string) string {
	h := sha256.Sum256([]byte(principal + "\x00" + device))
	return devicePrefix + hex.EncodeToString(h[:16])
}

// deviceToken serves /device/token on the internal listener: POST redeems a code (no credential:
// the code and verifier are the credential), DELETE signs the presented device token out.
func (b *Broker) deviceToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Code     string `json:"code"`
			Verifier string `json:"verifier"`
			Port     int    `json:"port"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		// Any attempt consumes the code, a malformed verifier included (Lean `redeem`): an empty
		// hash never equals a challenge.
		verifierHash := ""
		if reVerifier.MatchString(body.Verifier) {
			sum := sha256.Sum256([]byte(body.Verifier))
			verifierHash = base64.RawURLEncoding.EncodeToString(sum[:])
		}
		c, ok := b.device.redeem(body.Code, verifierHash, body.Port, b.now())
		if !ok || verifierHash == "" {
			writeErr(w, http.StatusBadRequest, apiError{Code: "invalid_grant", Message: "sign-in not completed"})
			return
		}
		name := deviceName(c.principal, c.device)
		version := b.currentVersion()
		tok, exp, err := b.tokens.IssueDevice(name, c.principal, b.cfg.HumanPrincipals,
			time.Duration(b.cfg.DeviceTokenTTLHours)*time.Hour, b.cfg.MaxDeviceTokens, b.now(),
			func(tx *sql.Tx) error {
				return b.store.AuditTx(tx, AuditRecord{Kind: "token_issue", Actor: "device-login", Name: name,
					Principal: auditSafe(c.principal), Version: version})
			})
		if errors.Is(err, errIssue) {
			writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "refused", Message: "principal not allowed"})
			return
		}
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "store_unavailable", Message: "token not issued"})
			return
		}
		log.Printf("device token issued device=%s principal=%s expires=%s", name, auditSafe(c.principal), exp.Format(time.RFC3339))
		writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "expires_at": exp, "principal": c.principal})
	case http.MethodDelete:
		auth := r.Header.Values("Authorization")
		if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") {
			failure(w, http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(auth[0], "Bearer ")
		rec, ok, err := b.tokens.Lookup(tok, b.now())
		if err != nil {
			// The registry cannot say whether the token is revoked: sign-out has not happened.
			failure(w, http.StatusServiceUnavailable)
			return
		}
		if !ok {
			failure(w, http.StatusUnauthorized)
			return
		}
		if !rec.Device {
			// Workspace tokens belong to the provisioner; a workspace cannot sign itself out.
			failure(w, http.StatusForbidden)
			return
		}
		gone, found, err := b.tokens.RevokeToken(tok)
		if err != nil {
			failure(w, http.StatusServiceUnavailable)
			return
		}
		if !found {
			failure(w, http.StatusUnauthorized)
			return
		}
		if b.store.Audit(AuditRecord{Kind: "token_revoke", Actor: "device-logout", Name: gone.Workspace,
			Principal: auditSafe(gone.Principal), Version: b.currentVersion()}) != nil {
			log.Printf("device token revoked device=%s but the revocation could not be audited", gone.Workspace)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		failure(w, http.StatusMethodNotAllowed)
	}
}
