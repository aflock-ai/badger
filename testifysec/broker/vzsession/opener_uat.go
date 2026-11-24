//go:build uatsignin

package vzsession

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

// headlessSignIn is true only in the session UAT build (-tags uatsignin).
const headlessSignIn = true

// In the UAT build no person is present: the "browser" fetches the approval page, whose fixture
// edge approves at once and redirects to the loopback callback. The exchange that follows still
// uses the pinned edge client; this only stands in for the person's browser.
// Nobody waits on a person here, so the deadline is short enough for the harness's command limit
// to see sign-in fail, by code and with its log line, instead of killing a silent process.
func init() {
	signInDeadline = 30 * time.Second
	browserOpener = func(ctx context.Context, u string) error {
		client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, res.Body)
		return res.Body.Close()
	}
}
