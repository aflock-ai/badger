package vzsession

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Device sign-in (badger-broker device.go). At session start this host process, never the VM or
// the TUI, signs the person in: it opens their browser at the edge's approval page, receives the
// one-time code on a loopback listener, and redeems it with its PKCE verifier for a broker token.
// The token lives only in this process's memory and in the gateway's, which gets it over an
// inherited pipe (gateway providerTokenFd). It is never written to disk, an environment variable
// or an argument, and the session signs it out at the end.

// brokerSignIn is the gateway template's sign-in assignment: where the edge serves the broker,
// its certificate pin (SPKI SHA-256, lowercase hex; empty if a system root signs it), and where
// the stable, non-secret device id lives (absolute; empty means the user's config directory).
type brokerSignIn struct {
	EdgeURL        string `json:"edgeUrl"`
	EdgeCertSHA256 string `json:"edgeCertSha256"`
	DeviceIDFile   string `json:"deviceIdFile"`
}

const (
	authorizePath = "/device/authorize"
	tokenPath     = "/device/token"
)

var (
	// A person approving in the browser; the session limit starts after it. The UAT build, where
	// nobody approves by hand, shortens it to fit inside its harness's command limit.
	signInDeadline = 5 * time.Minute
	// openerRequired makes a failed open end sign-in at once. Only the UAT build sets it: its
	// opener is the only thing that can approve, so a failure there would otherwise wait out the
	// deadline in silence. A person can still open the printed URL when their browser does not.
	openerRequired = headlessSignIn
	// signInLog receives one line per sign-in step. It never sees the token, verifier or code.
	signInLog io.Writer = os.Stderr
)

var (
	reBrokerToken = regexp.MustCompile(`^bbt_[A-Za-z0-9_-]{43}$`)
	reDeviceID    = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	rePin         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (b *brokerSignIn) validate() error {
	u, err := url.Parse(b.EdgeURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawPath != "" || !rePathPrefix.MatchString(u.Path) || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return refused("broker_signin_edge")
	}
	if b.EdgeCertSHA256 != "" && !rePin.MatchString(b.EdgeCertSHA256) {
		return refused("broker_signin_pin")
	}
	if b.DeviceIDFile != "" && !absolute(b.DeviceIDFile) {
		return refused("broker_signin_device")
	}
	return nil
}

// base is where the edge serves the broker, for example https://edge.example.test/broker: the
// approval page, the code exchange and the model API are under it.
func (b *brokerSignIn) base() string { return b.EdgeURL }

// client talks to the edge only: no proxy, no redirects, and with a pin exactly that key.
func (b *brokerSignIn) client() *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if b.EdgeCertSHA256 != "" {
		cfg.InsecureSkipVerify = true // replaced by the pin check below, never skipped
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no edge certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if hex.EncodeToString(sum[:]) != b.EdgeCertSHA256 {
				return errors.New("edge certificate does not match its pin")
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, TLSClientConfig: cfg},
	}
}

// deviceID reads the device's id, creating it on first use (0600, parent 0700).
func (b *brokerSignIn) deviceID() (string, error) {
	path := b.DeviceIDFile
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(dir, "badger", "device-id")
	}
	if id, found, err := readDeviceID(path); found || err != nil {
		return id, err
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	// Publish the whole id at once: write a private temporary file, then hard-link it into place.
	// The link fails if another session got there first, and then that session's id is the device's.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".device-id-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(id + "\n")
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o600)
	}
	if err != nil {
		return "", err
	}
	if err = os.Link(tmp.Name(), path); errors.Is(err, os.ErrExist) {
		// Another session published first: use its id, once. Anything but a valid regular file
		// there is refused, never retried.
		id, found, err := readDeviceID(path)
		if err == nil && !found {
			err = refused("broker_signin_device")
		}
		return id, err
	}
	return id, err
}

// readDeviceID reads an existing device id. found is false only when nothing is at path; a
// symlink, directory or malformed id is refused.
func readDeviceID(path string) (id string, found bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() {
		return "", true, refused("broker_signin_device")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", true, err
	}
	id = strings.TrimSpace(string(raw))
	if !reDeviceID.MatchString(id) {
		return "", true, refused("broker_signin_device")
	}
	return id, true, nil
}

func randomB64(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// openBrowser shows the approval page. The URL goes to stderr too, for a person whose browser does
// not open by itself; it carries no secret (the challenge is a hash, the state is checked here).
func openBrowser(ctx context.Context, u string) error {
	fmt.Fprintf(os.Stderr, "Approve this session in your browser: %s\n", u)
	if runtime.GOOS != "darwin" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/open", u)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	return cmd.Run()
}

// deviceToken is a signed-in device's broker token, held in memory only.
type deviceToken struct {
	signIn *brokerSignIn
	token  string
}

// signIn runs the device flow and returns the broker token. open shows the approval URL.
func (b *brokerSignIn) signIn(ctx context.Context, open func(context.Context, string) error) (*deviceToken, error) {
	ctx, cancel := context.WithTimeout(ctx, signInDeadline)
	defer cancel()
	deviceID, err := b.deviceID()
	if err != nil {
		fmt.Fprintf(signInLog, "broker sign-in: device id file unusable: %v\n", err)
		return nil, refused("broker_signin_device")
	}
	// Each session signs in as its own device record (the device id plus a random suffix): two
	// sessions on one computer must not replace each other's token. Each signs its own out at the
	// end; the broker keeps at most its per-person cap of them live.
	suffix, err := randomB64(8)
	if err != nil {
		return nil, err
	}
	device := deviceID + "-" + suffix
	verifier, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	state, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(signInLog, "broker sign-in: loopback listener: %v\n", err)
		return nil, refused("broker_signin_listener")
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	codes := make(chan string, 1)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/callback" || len(q) != 2 || len(q["code"]) != 1 || len(q["state"]) != 1 ||
			q.Get("state") != state || q.Get("code") == "" || len(q.Get("code")) > 128 {
			http.Error(w, "This is not the sign-in this session started. Close this page.", http.StatusBadRequest)
			return
		}
		select {
		case codes <- q.Get("code"):
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, "Signed in. You can close this page and return to Badger.")
		default:
			http.Error(w, "Already signed in.", http.StatusConflict)
		}
	})}
	go srv.Serve(listener)
	defer srv.Close()
	q := url.Values{"challenge": {challenge}, "port": {strconv.Itoa(port)}, "state": {state}, "device": {device}}
	// The browser opens in the background, bounded by the sign-in deadline: a stalled or failed
	// launch never holds the session, and the person can still open the printed URL.
	fmt.Fprintf(signInLog, "broker sign-in: waiting up to %s for approval at %s\n", signInDeadline, b.EdgeURL)
	opened := make(chan error, 1)
	go func() { opened <- open(ctx, b.base()+authorizePath+"?"+q.Encode()) }()
	var code string
wait:
	for {
		select {
		case code = <-codes:
			break wait
		case err := <-opened:
			opened = nil
			if err == nil {
				continue
			}
			fmt.Fprintf(signInLog, "broker sign-in: opening the approval page failed: %v\n", err)
			if openerRequired {
				return nil, refused("broker_signin_open")
			}
		case <-ctx.Done():
			fmt.Fprintf(signInLog, "broker sign-in: no approval within %s\n", signInDeadline)
			return nil, refused("broker_signin_timeout")
		}
	}
	fmt.Fprintln(signInLog, "broker sign-in: approved, exchanging the code")
	body, _ := json.Marshal(map[string]any{"code": code, "verifier": verifier, "port": port})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base()+tokenPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := b.client().Do(req)
	if err != nil {
		fmt.Fprintf(signInLog, "broker sign-in: exchange: %v\n", err)
		return nil, refused("broker_signin_exchange")
	}
	defer res.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	if res.StatusCode != http.StatusCreated || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&out) != nil || !reBrokerToken.MatchString(out.Token) {
		fmt.Fprintf(signInLog, "broker sign-in: exchange refused (HTTP %d)\n", res.StatusCode)
		return nil, refused("broker_signin_exchange")
	}
	fmt.Fprintln(signInLog, "broker sign-in: signed in")
	return &deviceToken{signIn: b, token: out.Token}, nil
}

// pipe returns the read end for the gateway (its providerTokenFd) after writing the token to it.
// The caller keeps w open for the session: closing it clears the gateway's credential.
func (d *deviceToken) pipe() (r, w *os.File, err error) {
	r, w, err = os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	if _, err = io.WriteString(w, d.token+"\n"); err != nil {
		r.Close()
		w.Close()
		return nil, nil, err
	}
	return r, w, nil
}

// signOut revokes the token at the broker. The session calls it once, at the end.
func (d *deviceToken) signOut(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, d.signIn.base()+tokenPath, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	res, err := d.signIn.client().Do(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("sign-out: %d", res.StatusCode)
	}
	return nil
}
