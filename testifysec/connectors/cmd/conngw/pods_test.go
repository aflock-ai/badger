package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

var imageDigest = "sha256:" + strings.Repeat("ab", 32)

// hostDigest is the plughost image digest the test profiles pin.
var hostDigest = "sha256:" + strings.Repeat("ee", 32)

// The pod status lookup reads the plugin container's image digest as the node reports it, and
// refuses a container that is not running or reports no digest.
func TestPodStatusNamesTheRunningImage(t *testing.T) {
	status := `{"status":{"containerStatuses":[` +
		`{"name":"x","containerID":"containerd://c1","imageID":"registry.example.invalid/x@` + imageDigest + `","state":{"running":{}}},` +
		`{"name":"waiting","containerID":"containerd://c2","imageID":"registry.example.invalid/x@` + imageDigest + `","state":{"waiting":{}}},` +
		`{"name":"tagonly","containerID":"containerd://c3","imageID":"registry.example.invalid/x:1","state":{"running":{}}},` +
		`{"name":"bare","containerID":"containerd://c4","imageID":"containerd://` + imageDigest + `","state":{"running":{}}},` +
		`{"name":"otherscheme","containerID":"containerd://c5","imageID":"docker-pullable://registry.example.invalid/x@` + imageDigest + `","state":{"running":{}}}]}}`
	var path, auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		_, _ = w.Write([]byte(status))
	}))
	defer srv.Close()
	k := &podStatus{url: srv.URL + "/api/v1/namespaces/conngw/pods/conngw-0", client: srv.Client(), tokenFile: writeFile(t, "token", "sa-token\n")}
	c, err := k.check(context.Background(), "x", imageDigest)
	if err != nil || c.id != "containerd://c1" {
		t.Fatalf("%+v %v", c, err)
	}
	if path != "/api/v1/namespaces/conngw/pods/conngw-0" || auth != "Bearer sa-token" {
		t.Fatalf("%q %q", path, auth)
	}
	// containerd reports a bare digest with its runtime prefix; that is the pinned image too.
	if c, err := k.check(context.Background(), "bare", imageDigest); err != nil || c.id != "containerd://c4" {
		t.Fatalf("bare runtime-prefixed digest: %+v %v", c, err)
	}
	// A state that is not an object of states (here "running": false) refuses the whole status.
	malformed := strings.Replace(status, `"state":{"running":{}}`, `"state":{"running":false}`, 1)
	srvBad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(malformed)) }))
	defer srvBad.Close()
	bad := &podStatus{url: srvBad.URL, client: srvBad.Client(), tokenFile: k.tokenFile}
	if _, err := bad.check(context.Background(), "x", imageDigest); err == nil {
		t.Error("malformed running state accepted")
	}
	for _, c := range []struct{ name, digest string }{
		{"x", "sha256:" + strings.Repeat("cd", 32)}, {"waiting", imageDigest}, {"tagonly", imageDigest}, {"absent", imageDigest},
		{"otherscheme", imageDigest},
	} {
		if _, err := k.check(context.Background(), c.name, c.digest); err == nil {
			t.Errorf("%s %s: accepted", c.name, c.digest)
		}
	}
}

// The pod status URL names the pod by the Downward API's metadata.name and metadata.namespace
// (POD_NAME, POD_NAMESPACE), never the hostname, which spec.hostname or setHostnameAsFQDN can make
// another name. Missing or malformed, the gateway does not start.
func TestThePodIsNamedByTheDownwardAPI(t *testing.T) {
	env := map[string]string{"POD_NAME": "conngw-7d9f8-abcde", "POD_NAMESPACE": "conngw", "HOSTNAME": "conngw.example.invalid"}
	u, err := podURL(func(k string) string { return env[k] })
	if err != nil || u != "https://kubernetes.default.svc/api/v1/namespaces/conngw/pods/conngw-7d9f8-abcde" {
		t.Fatalf("%q %v", u, err)
	}
	for name, e := range map[string]map[string]string{
		"no name":         {"POD_NAMESPACE": "conngw"},
		"no namespace":    {"POD_NAME": "conngw-0"},
		"name with slash": {"POD_NAME": "a/b", "POD_NAMESPACE": "conngw"},
		"bad namespace":   {"POD_NAME": "conngw-0", "POD_NAMESPACE": "Conngw"},
	} {
		if _, err := podURL(func(k string) string { return e[k] }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A redirect from the status URL is refused and the place it names is never contacted.
func TestPodStatusRefusesRedirects(t *testing.T) {
	var hit atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer elsewhere.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/api/v1/namespaces/conngw/pods/conngw-0", http.StatusFound)
	}))
	defer srv.Close()
	k := &podStatus{url: srv.URL, client: srv.Client(), tokenFile: writeFile(t, "token", "sa-token\n")}
	if _, err := k.check(context.Background(), "x", imageDigest); err == nil || hit.Load() {
		t.Fatalf("redirect followed: %v, contacted %v", err, hit.Load())
	}
}

// The image ID is read as the node reports it: an optional containerd:// or docker:// runtime prefix,
// then "<repository>@sha256:<hex>" or the bare digest. Any other scheme, or a second one, is refused
// rather than guessed at.
func TestTheImageIDIsNormalised(t *testing.T) {
	for id, want := range map[string]string{
		"containerd://registry.example.invalid/x@" + imageDigest: imageDigest,
		"docker://registry.example.invalid/x@" + imageDigest:     imageDigest,
		"registry.example.invalid:5000/x@" + imageDigest:         imageDigest,
		"containerd://" + imageDigest:                            imageDigest,
		"docker://" + imageDigest:                                imageDigest,
		imageDigest:                                              imageDigest,
		"registry.example.invalid/x:1":                           "registry.example.invalid/x:1",
	} {
		if got, err := imageDigestOf(id); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", id, got, err, want)
		}
	}
	for _, id := range []string{
		"docker-pullable://registry.example.invalid/x@" + imageDigest,
		"cri-o://" + imageDigest,
		"://" + imageDigest,
		"containerd://docker://" + imageDigest,
		"containerd://evil://registry.example.invalid/x@" + imageDigest,
	} {
		if got, err := imageDigestOf(id); err == nil {
			t.Errorf("%q: accepted as %q", id, got)
		}
	}
}
