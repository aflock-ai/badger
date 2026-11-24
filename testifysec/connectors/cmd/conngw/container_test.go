//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/launch"
)

// pinned answers pod status: the next of ids each call (last repeats), as a running container of digest.
type pinned struct {
	mu     sync.Mutex
	digest string
	ids    []string
	calls  int
}

func id(hex string) string { return "containerd://" + strings.Repeat(hex, 32) }

func (p *pinned) check(_ context.Context, name, digest string) (container, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if name != "x" || p.digest != digest {
		return container{}, errors.New("not the pinned image")
	}
	return container{id: id(p.ids[min(p.calls, len(p.ids))-1])}, nil
}

func inProc(t *testing.T, hex string) {
	t.Helper()
	saved := procRoot
	procRoot = fakeProc(t, map[string]string{strconv.Itoa(os.Getpid()): "0::/../cri-containerd-" + strings.Repeat(hex, 32) + ".scope\n"})
	t.Cleanup(func() { procRoot = saved })
}

func listener(t *testing.T) (string, chan string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "plugin.sock")
	l, err := launch.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	hellos := make(chan string, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				hellos <- line
			}()
		}
	}()
	return sock, hellos
}

func containerSource(t *testing.T, sock string) source {
	s := mustSource(t, "x", levels(t)[1])
	// The container runs the plughost image (imageDigest here); the plugin executable has its own digest.
	s.Socket, s.host, s.Digest, s.UID, s.GID = sock, imageDigest, "sha256:"+strings.Repeat("5e", 32), os.Getuid(), os.Getgid()
	s.Flags = map[string]string{"auth": "bearer"}
	return s
}

// The plugin is reached only while the pod's status says its container runs the pinned plughost
// image, the same one before and after connecting; otherwise the stream is refused before a byte
// reaches it. A container substituted with the vendor's own image (whatever its entrypoint serves on
// the socket) runs another image, so it is refused too.
func TestOnlyThePinnedImageIsReached(t *testing.T) {
	sock, _ := listener(t)
	inProc(t, "c1")
	s := containerSource(t, sock)
	for name, p := range map[string]*pinned{
		"another digest":          {digest: "sha256:" + strings.Repeat("cd", 32), ids: []string{"c1"}},
		"the vendor's image":      {digest: "sha256:" + strings.Repeat("7e", 32), ids: []string{"c1"}},
		"the executable's digest": {digest: s.Digest, ids: []string{"c1"}}, // a profile digest is never an image pin
		"container changed":       {digest: imageDigest, ids: []string{"c1", "c2"}},
		"replaced, status stale":  {digest: imageDigest, ids: []string{"c0"}}, // status lags a replacement
	} {
		if proc, err := dial(context.Background(), s, p.check); err == nil {
			proc.stop()
			t.Errorf("%s: dialled", name)
		}
	}
}

// The socket must be answered by the plugin's own uid and gid (another plugin's socket, linked in,
// is refused).
func TestThePluginSocketMustBelongToItsUser(t *testing.T) {
	sock, _ := listener(t)
	inProc(t, "c1")
	ok := (&pinned{digest: imageDigest, ids: []string{"c1"}}).check
	for name, edit := range map[string]func(*source){
		"another uid": func(s *source) { s.UID++ },
		"another gid": func(s *source) { s.GID++ },
	} {
		s := containerSource(t, sock)
		edit(&s)
		if p, err := dial(context.Background(), s, ok); err == nil {
			p.stop()
			t.Errorf("%s: dialled", name)
		}
	}
}

// The hello is all the plugin learns from the gateway: its own settings, no gateway state.
func TestTheHelloCarriesOnlyThePluginsSettings(t *testing.T) {
	sock, hellos := listener(t)
	inProc(t, "c1")
	s := containerSource(t, sock)
	s.Writes = true
	p, err := dial(context.Background(), s, (&pinned{digest: imageDigest, ids: []string{"c1"}}).check)
	if err != nil {
		t.Fatal(err)
	}
	defer p.stop()
	want := launch.Hello{Version: 1, BaseURL: s.BaseURL, TokenPath: s.TokenPath, Classification: levels(t)[1], Writes: true, Flags: map[string]string{"auth": "bearer"}, PluginDigest: s.Digest}
	// The hello is exactly the plugin's settings and nothing of the gateway's own state.
	if got := strings.TrimSpace(<-hellos); got != mustJSON(want) {
		t.Fatalf("hello %s, want %s", got, mustJSON(want))
	}
}
