// Package fakeserver stands up an httptest fake of an enclave service from recorded JSON
// fixtures, for connector tests. Routes match on method, escaped path and (optionally) query;
// anything unmatched fails the test and answers 404. Every request is recorded so a test can
// assert what the connector sent.
//
// Record fixtures from a real self-managed instance with a throwaway account, then scrub hosts,
// names and identifiers to example.invalid values before committing them.
package fakeserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Route is one canned response.
type Route struct {
	Method  string // GET, POST, ...
	Path    string // escaped path as sent, e.g. /api/v4/projects/group%2Fproject
	Query   string // if set, must equal the request query (order-insensitive)
	Status  int    // default 200
	Fixture string // file under the fixtures directory, served as the body
	Body    string // inline body, used when Fixture is empty
	// EchoAuth answers with the credential headers the connector sent, standing in for a service
	// that reflects them. Tests use it to prove the credential never reaches tool output.
	EchoAuth bool
	Header   map[string]string
	// Responses, when set, answers the first matching request with Responses[0], the second with
	// Responses[1], and so on; the last one repeats. Status, Fixture, Body and Header above are
	// then ignored.
	Responses []Response
}

// Response is one answer in a Route's sequence.
type Response struct {
	Status  int
	Fixture string
	Body    string
	Header  map[string]string
}

// Request is what the fake received.
type Request struct {
	Method, Path, RawQuery string
	Header                 http.Header
	Body                   []byte
}

type Server struct {
	*httptest.Server
	mu       sync.Mutex
	requests []Request
}

// New starts a plain-HTTP loopback fake (connectors under test need InsecureLoopbackHTTP) and
// closes it when the test ends.
func New(t testing.TB, fixtures string, routes ...Route) *Server {
	t.Helper()
	s := &Server{}
	hits := make([]int, len(routes))
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, Request{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Clone(), body})
		s.mu.Unlock()
		for i, rt := range routes {
			if rt.Method != r.Method || rt.Path != r.URL.EscapedPath() || !sameQuery(rt.Query, r.URL.RawQuery) {
				continue
			}
			if len(rt.Responses) > 0 {
				s.mu.Lock()
				next := rt.Responses[min(hits[i], len(rt.Responses)-1)]
				hits[i]++
				s.mu.Unlock()
				rt.Status, rt.Fixture, rt.Body, rt.Header = next.Status, next.Fixture, next.Body, next.Header
			}
			payload := []byte(rt.Body)
			if rt.Fixture != "" {
				b, err := os.ReadFile(filepath.Join(fixtures, rt.Fixture))
				if err != nil {
					t.Errorf("fakeserver: fixture %s: %v", rt.Fixture, err)
				}
				payload = b
			}
			if rt.EchoAuth {
				payload = []byte(`{"seen":"` + r.Header.Get("Authorization") + r.Header.Get("PRIVATE-TOKEN") + `"}`)
			}
			w.Header().Set("Content-Type", "application/json")
			for k, v := range rt.Header {
				w.Header().Set(k, v)
			}
			if rt.Status != 0 {
				w.WriteHeader(rt.Status)
			}
			w.Write(payload)
			return
		}
		t.Errorf("fakeserver: no route for %s %s?%s", r.Method, r.URL.EscapedPath(), r.URL.RawQuery)
		http.NotFound(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func sameQuery(want, got string) bool {
	if want == "" {
		return true
	}
	w, err1 := url.ParseQuery(want)
	g, err2 := url.ParseQuery(got)
	return err1 == nil && err2 == nil && w.Encode() == g.Encode()
}

// Requests returns a copy of every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}
