package main

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"sync"
)

// credential is the provider token in memory. A file source sets it once at start; a pipe source
// (providerTokenFd) lets the process that signed the person in hand it over without it touching
// disk: each line replaces it, an invalid line or the pipe closing clears it, and an empty
// credential from a pipe source means no provider call.
type credential struct {
	mu sync.RWMutex
	v  string
}

func (c *credential) get() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.v
}

func (c *credential) set(v string) {
	c.mu.Lock()
	c.v = v
	c.mu.Unlock()
}

// follow reads tokens from r until it closes, then clears the credential.
func (c *credential) follow(r io.ReadCloser) {
	defer r.Close()
	defer c.set("")
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 8192), 8192)
	// Split on LF only: ScanLines would drop a CR before the LF and let "token\r\n" through.
	s.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for s.Scan() {
		line := s.Text()
		if line == "" || strings.ContainsAny(line, "\r\x00") {
			c.set("")
			continue
		}
		c.set(line)
	}
}
