package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// Send-up: a workspace sends a file to another workspace of the same owner whose label dominates its
// own, typically its fork. The pod decides, from the reviewed identities and the labels it keeps,
// never from anything the workspace says about itself. Nothing flows back: the sender gets
// "delivered" or "refused" and nothing else, and a workspace reads only its own inbox.
//
//	POST   /sendup        {"to":"<ns>/<account>","name":"<file name>","data":"<base64>"}
//	GET    /inbox         {"items":[{"id","from","fromLabel","at","name","size"}]}
//	GET    /inbox/<id>    the item, with its data
//	DELETE /inbox/<id>    acknowledges it
//
// Items are files on the labels volume, published whole (written to a temporary name, synced,
// renamed, directory synced) before "delivered" is sent.
//
// The only capacity limit is the sender's own quota (perSender sends in sendWindow). A limit on the
// receiver's inbox would let the receiver signal down: fill or empty it, and the sender's answers
// change. Nothing the receiver does changes what a sender is told. A store that fails (a full
// volume) stops send-up until a restart, so freeing space by deleting items does not reopen it
// either; the volume is sized for the senders' quotas.

const (
	maxItemBytes = 4 << 20
	sendWindow   = 24 * time.Hour
)

var (
	itemName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$`)
	itemID   = regexp.MustCompile(`^[0-9]{20}$`)
	errQuota = errors.New("the sender's send quota is used up")
)

// item is one delivered file.
type item struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	FromLabel string    `json:"fromLabel"` // the sender's label when it sent; "" = it had read nothing
	At        time.Time `json:"at"`
	Name      string    `json:"name"`
	Size      int       `json:"size"`
	Data      []byte    `json:"data,omitempty"`
}

// inbox keeps each workspace's received items in its own directory, named by a hash of the
// workspace, so no path is built from a workspace's name.
type inbox struct {
	dir  string
	mu   sync.Mutex
	last int64
	// perSender sends per sender in sendWindow, counted in memory (a restart, which the receiver
	// cannot cause, resets it).
	perSender int
	sent      map[string][]time.Time
	// write stores one file durably (writeSynced; tests replace it).
	write func(path string, b []byte) error
	// failed is the first store failure (a full volume, say). From then on every send is refused
	// until a restart: if a send could succeed again once space is freed, a receiver could signal a
	// sender by deleting items.
	failed error
}

// openInbox opens the inbox directory and removes any item left half written by a crash.
func openInbox(dir string) (*inbox, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("inbox directory must be absolute")
	}
	// The inbox goes in an existing directory (the labels volume). Its entry there, and each receiver
	// directory's entry in it, are synced at every start before any send is accepted, so a sync that
	// an interrupted earlier start never made is made now: a crash must not lose a directory and the
	// items it held.
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := syncDir(d); err != nil {
			return nil, err
		}
	}
	stray, err := filepath.Glob(filepath.Join(dir, "*", ".tmp-*"))
	if err != nil {
		return nil, err
	}
	for _, f := range stray {
		if err := os.Remove(f); err != nil {
			return nil, err
		}
	}
	return &inbox{dir: dir, perSender: 64, sent: map[string][]time.Time{}, write: writeSynced}, nil
}

func (in *inbox) path(ws string) string {
	h := sha256.Sum256([]byte(ws))
	return filepath.Join(in.dir, hex.EncodeToString(h[:16]))
}

// put stores an item for ws durably: the receiver's directory entry, the file and its name are
// all synced before it returns. The sender's quota is checked first.
func (in *inbox) put(ws string, it item) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.failed != nil {
		return in.failed
	}
	if err := in.store(ws, it); err != nil {
		if !errors.Is(err, errQuota) {
			in.failed = err
		}
		return err
	}
	return nil
}

func (in *inbox) store(ws string, it item) error {
	now := time.Now()
	recent := slices.DeleteFunc(in.sent[it.From], func(t time.Time) bool { return now.Sub(t) > sendWindow })
	if len(recent) >= in.perSender {
		in.sent[it.From] = recent
		return errQuota
	}
	in.sent[it.From] = append(recent, now)
	d := in.path(ws)
	if _, err := os.Stat(d); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(d, 0o700); err != nil {
			return err
		}
		// The new directory's entry in the inbox directory must be durable too.
		if err := syncDir(in.dir); err != nil {
			return err
		}
	}
	// Ids are increasing nanoseconds, so a listing is in arrival order.
	id := time.Now().UnixNano()
	if id <= in.last {
		id = in.last + 1
	}
	in.last = id
	it.ID = fmt.Sprintf("%020d", id)
	b, _ := json.Marshal(it)
	tmp := filepath.Join(d, ".tmp-"+it.ID)
	if err := in.write(tmp, b); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(d, it.ID+".json")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(d)
}

func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syncDir is a variable so a test can see which directories are synced.
var syncDir = func(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (in *inbox) get(ws, id string) (item, error) {
	var it item
	if !itemID.MatchString(id) {
		return it, os.ErrNotExist
	}
	b, err := os.ReadFile(filepath.Join(in.path(ws), id+".json"))
	if err != nil {
		return it, err
	}
	err = json.Unmarshal(b, &it)
	return it, err
}

func (in *inbox) list(ws string) ([]item, error) {
	entries, err := os.ReadDir(in.path(ws))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		// Only published items: a temporary file is never read.
		if id, ok := strings.CutSuffix(e.Name(), ".json"); ok && itemID.MatchString(id) {
			names = append(names, id)
		}
	}
	sort.Strings(names)
	out := []item{}
	for _, id := range names {
		it, err := in.get(ws, id)
		if errors.Is(err, os.ErrNotExist) {
			continue // acknowledged since the directory was read
		}
		if err != nil {
			return nil, err
		}
		it.Data = nil
		out = append(out, it)
	}
	return out, nil
}

func (in *inbox) remove(ws, id string) error {
	if !itemID.MatchString(id) {
		return os.ErrNotExist
	}
	if err := os.Remove(filepath.Join(in.path(ws), id+".json")); err != nil {
		return err
	}
	// The removal is durable before it is acknowledged: a crash must not bring the item back.
	return syncDir(in.path(ws))
}

// sendable decides a send from the pod's own records: both registered to one owner, different
// workspaces, and the receiver's label dominating the sender's. A workspace that has read nothing is
// below every label.
func (l *labels) sendable(from, to string) (string, bool) {
	fl, fLabelled, fOwner, _, fReg := l.describe(from)
	tl, tLabelled, tOwner, _, tReg := l.describe(to)
	if !fReg || !tReg || fOwner != tOwner || from == to {
		return "", false
	}
	if !fLabelled {
		return "", true
	}
	return marking.Banner(fl), tLabelled && marking.Dominates(tl, fl)
}

// readable: an item is passed to its receiver only while the receiver's label dominates the
// sender's at the time (always, unless an administrator reset the receiver's label).
func (l *labels) readable(ws string, it item) bool {
	if it.FromLabel == "" {
		return true
	}
	m, err := marking.Parse(it.FromLabel)
	label, labelled, _, _, _ := l.describe(ws)
	return err == nil && labelled && marking.Dominates(label, m)
}

func (g *gateway) serveSendUp(w http.ResponseWriter, r *http.Request) {
	// As for the admin API (admin.go): every answer closes the connection, so a declared body that
	// never arrives is not waited for, and a body that is read is read under a deadline.
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(cmp.Or(g.adminRead, 5*time.Second)))
	if g.inbox == nil {
		http.NotFound(w, r)
		return
	}
	ws, ok := g.authenticate(w, r, func(ctx context.Context, token string) (string, error) {
		return g.review.workspace(ctx, token)
	})
	if !ok {
		return
	}
	id, one := strings.CutPrefix(r.URL.Path, "/inbox/")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/sendup":
		g.sendUp(w, r, ws)
	case r.Method == http.MethodGet && r.URL.Path == "/inbox":
		items, err := g.inbox.list(ws)
		if err != nil {
			g.log.Error("inbox unreadable", "workspace", ws, "err", err)
			http.Error(w, "inbox unavailable", http.StatusServiceUnavailable)
			return
		}
		items = slices.DeleteFunc(items, func(it item) bool { return !g.labels.readable(ws, it) })
		writeJSON(w, map[string]any{"items": items})
	case r.Method == http.MethodGet && one:
		it, err := g.inbox.get(ws, id)
		if err != nil || !g.labels.readable(ws, it) {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, it)
	case r.Method == http.MethodDelete && one:
		// An item the receiver may not read is not found for a delete either.
		it, err := g.inbox.get(ws, id)
		if err != nil || !g.labels.readable(ws, it) {
			http.NotFound(w, r)
			return
		}
		if err := g.inbox.remove(ws, id); errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			g.log.Error("acknowledgement not recorded", "workspace", ws, "err", err)
			http.Error(w, "inbox unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]string{"status": "removed"})
	default:
		http.NotFound(w, r)
	}
}

func (g *gateway) sendUp(w http.ResponseWriter, r *http.Request, from string) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxItemBytes*4/3+4<<10))
	var in struct {
		To   string `json:"to"`
		Name string `json:"name"`
		Data []byte `json:"data"`
	}
	if err == nil {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		err = d.Decode(&in)
	}
	if err != nil || !itemName.MatchString(in.Name) || strings.Contains(in.Name, "..") || len(in.Data) > maxItemBytes {
		http.Error(w, "unreadable request", http.StatusBadRequest)
		return
	}
	refused := func(reason string) {
		// One answer for every refusal: the sender learns nothing about the receiver but that.
		g.log.Warn("send-up refused", "from", from, "reason", reason)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"status":"refused"}`+"\n")
	}
	ns, account, ok := strings.Cut(in.To, "/")
	if !ok || !slices.Contains(g.namespaces, ns) || !dnsLabel.MatchString(account) {
		refused("not a workspace this pod serves")
		return
	}
	fromLabel, ok := g.labels.sendable(from, in.To)
	if !ok {
		refused("not the same owner, or not upward")
		return
	}
	if err := g.inbox.put(in.To, item{From: from, FromLabel: fromLabel, At: time.Now().UTC(), Name: in.Name, Size: len(in.Data), Data: in.Data}); err != nil {
		if errors.Is(err, errQuota) {
			refused("sender quota")
			return
		}
		g.log.Error("send-up not stored; send-up is stopped until a restart", "from", from, "err", err)
		refused("not stored")
		return
	}
	g.log.Info("sent up", "from", from, "to", in.To, "fromLabel", fromLabel)
	writeJSON(w, map[string]string{"status": "delivered"})
}
