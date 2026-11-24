//go:build unix

package launch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Stage copies the plugin executable into dir while hashing it, and returns the copy's path only if
// the copied bytes are the digest the hello names, which comes from the administrator's signed
// profile. The executable is the vendor's, mounted read-only into this platform-built container
// from the vendor's image (an image volume, which runs nothing). The copy, not the mounted file,
// is what runs: the bytes executed are the bytes hashed, whatever the mount's options (an image
// volume may be noexec), and a plugin cannot change them (Landlock refuses it every write). No
// vendor code runs before this check, and what runs after it runs sandboxed. The vendor chose the
// image's contents, so exe must name a regular file itself (not a link, a device or a pipe) of at
// most MaxPlugin bytes, and exactly that many are read: the check always ends. The refusal names
// the digest found, so an operator can see which build is mounted.
func Stage(dir, exe, digest string) (string, error) {
	if !pluginDigest.MatchString(digest) {
		return "", errors.New("the plugin digest must be sha256:<hex>")
	}
	f, err := os.OpenFile(exe, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errors.New("the plugin executable cannot be opened as a file (a link, or missing)")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > MaxPlugin {
		return "", fmt.Errorf("the plugin executable must be a regular file of at most %d bytes", MaxPlugin)
	}
	d := filepath.Join(dir, strings.TrimPrefix(digest, "sha256:"))
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(d, ".partial-")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // gone once renamed
	h := sha256.New()
	n, err := io.CopyN(io.MultiWriter(h, tmp), f, fi.Size())
	if cerr := tmp.Close(); err != nil || cerr != nil || n != fi.Size() {
		return "", errors.New("the plugin executable cannot be read")
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != digest {
		return "", fmt.Errorf("the plugin executable is %s, not the digest the profile pins; refused", got)
	}
	if err := checkStatic(tmp.Name()); err != nil {
		return "", err
	}
	// Named as the mounted file, so records about the process carry the plugin's own name.
	run := filepath.Join(d, filepath.Base(exe))
	if err := os.Chmod(tmp.Name(), 0o500); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), run); err != nil {
		return "", err
	}
	return run, nil
}

// stage keeps one verified copy of this host's plugin, for the digest the last hello named, so it
// is copied once. Its directory is fixed for the socket and emptied when the host starts: an emptyDir outlives a
// container restart, and the copies left by an earlier run are reclaimed, not added to. A hello
// naming another digest (a re-signed profile) replaces the copy; a stream already running the old
// one keeps it until it exits.
type stage struct {
	dir    string
	mu     sync.Mutex
	digest string
	run    string
}

func newStage(dir string) (*stage, error) {
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	return &stage{dir: dir}, nil
}

func (st *stage) plugin(exe, digest string) (string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.run != "" && st.digest == digest {
		return st.run, nil
	}
	run, err := Stage(st.dir, exe, digest)
	if err != nil {
		_ = os.RemoveAll(filepath.Join(st.dir, strings.TrimPrefix(digest, "sha256:")))
		return "", err
	}
	if st.run != "" {
		_ = os.RemoveAll(filepath.Dir(st.run))
	}
	st.digest, st.run = digest, run
	return run, nil
}

// MaxPlugin bounds the executable plughost hashes per stream.
const MaxPlugin = 256 << 20

// Listen opens the plugin's socket. Its directory is shared only with the gateway's container, which
// runs as another user, so the socket is open to any user (0666). The gateway checks who answers it.
func Listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path) // a socket left by the previous run of this container
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Grace is how long a plugin may run after its input ends: longer than the gateway's own bound on
// a call.
var Grace = 3 * time.Minute

// MaxPending bounds the input a plugin has not read yet; chunk is the read size.
const (
	MaxPending = 16 << 20
	chunk      = 32 << 10
)

// killedByTeardown reports a plugin stopped by the host's own SIGKILL at the stream's end.
func killedByTeardown(ee *exec.ExitError) bool {
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}

// HideEnv names the directories the plugin must not read, ':'-separated: the vendor image's mount
// (where the unverified executable sits) and the mounted token's directory (the plugin reads only
// its stream's snapshot). Serve sets it for the shim; the plugin's environment never holds it.
const HideEnv = "BADGER_SANDBOX_HIDE"

// ReadEnv names the single files, ':'-separated, the plugin may read in the otherwise hidden staging
// directory: its own stream's token snapshot and, when the profile names a CA file, its stream's
// copy of the certificates in it.
const ReadEnv = "BADGER_SANDBOX_READ"

// snapshotCA checks the hello's CA file and writes a fresh copy of its certificates for one stream
// into dir (the staging directory); the plugin is given that copy (--ca-file), never the original.
// The file must resolve inside its own directory (a Secret volume's ..data links do), must not be
// the token file, must be a regular file of at most 1 MiB, and must hold PEM CERTIFICATE blocks only,
// each a certificate that parses, with nothing but whitespace around them. A private key or any other
// block refuses the stream. The copy holds the parsed certificates re-encoded, so no other byte of the
// original can reach the plugin.
func snapshotCA(dir, caPath, tokenPath string) (string, error) {
	r, err := filepath.EvalSymlinks(caPath)
	if err != nil {
		return "", errors.New("caPath cannot be resolved; refused")
	}
	d, err := filepath.EvalSymlinks(filepath.Dir(caPath))
	if err != nil || !inside(r, d) {
		return "", errors.New("caPath must resolve inside its own directory (no link out of it); refused")
	}
	if t, err := filepath.EvalSymlinks(tokenPath); err == nil && t == r {
		return "", errors.New("caPath is the token file; refused")
	}
	f, err := os.OpenFile(r, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errors.New("caPath cannot be opened; refused")
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return "", errors.New("caPath must be a regular file of at most 1 MiB; refused")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return "", errors.New("caPath must be a regular file of at most 1 MiB; refused")
	}
	var out []byte
	rest := b
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 && len(out) > 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return "", errors.New("caPath must hold only PEM CERTIFICATE blocks, with nothing else between or around them; refused")
		}
		var block *pem.Block
		before := bytes.Count(rest, []byte("-----BEGIN "))
		block, rest = pem.Decode(rest)
		if block == nil || before-bytes.Count(rest, []byte("-----BEGIN ")) != 1 {
			return "", errors.New("caPath holds a malformed PEM block; refused")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return "", fmt.Errorf("caPath holds a PEM %q block; only CERTIFICATE blocks may be given to a plugin; refused", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", errors.New("caPath holds a CERTIFICATE block that does not parse; refused")
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
	}
	c, err := os.CreateTemp(dir, "ca-")
	if err != nil {
		return "", err
	}
	_, werr := c.Write(out)
	if cerr := c.Close(); werr != nil || cerr != nil || os.Chmod(c.Name(), 0o400) != nil {
		os.Remove(c.Name())
		return "", errors.New("the CA could not be copied for the stream; refused")
	}
	return c.Name(), nil
}

// tmpfsMagic is TMPFS_MAGIC: statfs's f_type for a memory-backed filesystem.
const tmpfsMagic = 0x01021994

// checkMemoryBacked refuses a staging directory that is not tmpfs: token snapshots must never reach
// a disk, and must not outlive a crash.
func checkMemoryBacked(dir string) error {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return err
	}
	if int64(fs.Type) != tmpfsMagic {
		return fmt.Errorf("the staging directory %s is not memory-backed (tmpfs); mount an emptyDir with medium: Memory at the plugin host's TMPDIR (/tmp), so token snapshots never reach disk", dir)
	}
	return nil
}

// hiddenDirs is the HideEnv value for a stream: the vendor image's mount and the mounted token's
// directory. Neither may be / or hold the staging directory (where the verified copy and the
// snapshot are), and none may contain ':'.
func hiddenDirs(staging, vendor, token string) (string, error) {
	sr, err := filepath.EvalSymlinks(staging)
	if err != nil {
		return "", err
	}
	tokenDir, err := tokenRoot(token)
	if err != nil {
		return "", err
	}
	var dirs []string
	for _, p := range []string{vendor, tokenDir} {
		d, err := filepath.EvalSymlinks(p)
		if err != nil || d == "/" || strings.Contains(d, ":") || sr == d || inside(sr, d) {
			return "", errors.New("the vendor image's and the token's directories must be their own mounts, apart from the staging directory; refused")
		}
		dirs = append(dirs, d)
	}
	// The token file must resolve inside the hidden token directory (a Secret volume's token is a
	// link through ..data into a dated directory beside it, all beneath the mount), so no rotated
	// copy of it is readable by way of a link to somewhere else.
	own, err := filepath.EvalSymlinks(filepath.Dir(token))
	if r, rerr := filepath.EvalSymlinks(token); err != nil || rerr != nil || !inside(r, own) || !inside(r, dirs[1]) {
		return "", errors.New("the token file must resolve inside its own directory (no link out of the token mount); refused")
	}
	// The staging directory is hidden as a whole: other streams' token snapshots are there. The
	// stream's own snapshot (ReadEnv) and the verified copy get rules of their own.
	return strings.Join(append(dirs, sr), ":"), nil
}

// tokenRoot is the directory to hide for the token: its directory, unless the resolved token sits
// in a Kubernetes atomic-writer generation (a path component named "..<timestamp>", reached through
// ..data). Then it is the directory holding that generation, which holds every other generation
// too, so a token rotated in while a stream is open is hidden with the old one. This covers a token
// in a nested projection (credentials -> ..data/credentials) as well as the plain one.
func tokenRoot(token string) (string, error) {
	r, err := filepath.EvalSymlinks(token)
	if err != nil {
		return "", errors.New("the token file cannot be resolved; refused")
	}
	root := filepath.Dir(r)
	for d := filepath.Dir(r); d != "/" && d != "."; d = filepath.Dir(d) {
		if b := filepath.Base(d); strings.HasPrefix(b, "..") && b != ".." {
			root = filepath.Dir(d) // the highest generation directory wins
		}
	}
	return root, nil
}

// CheckVendorMount refuses a vendor directory that is not a mount point (/proc/self/mountinfo): the
// whole image volume must be hidden from the plugin, not a directory inside it.
func CheckVendorMount(dir string) error {
	r, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("-vendor %s: %w", dir, err)
	}
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("cannot read the mount table: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 4 && unescapeMount(f[4]) == r {
			return nil
		}
	}
	return fmt.Errorf("-vendor %s is not a mount point: it must be the vendor image volume's mountPath", dir)
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// inside reports whether the resolved path p is beneath the resolved directory dir, / included.
func inside(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if dir == "/" {
		return len(p) > 1 && p[0] == '/'
	}
	return strings.HasPrefix(p, dir+"/")
}

// osPipe makes a stream's stdin and stdout pipes (tests replace it to fail).
var osPipe = os.Pipe

// Serve accepts streams until l is closed, at most max at once (more are closed at once), and runs
// exe for each. Only a connection from the gateway's uid is served: the socket is open to any user,
// and the plugins themselves run as this host's.
func Serve(l net.Listener, exe string, max, gateway int) error {
	return ServeVendor(l, exe, filepath.Dir(exe), max, gateway)
}

// ServeVendor is Serve with the vendor image's mount named: the directory, holding exe, that the
// plugin must not read. plughost passes its -vendor flag (the image volume's mountPath).
func ServeVendor(l net.Listener, exe, vendor string, max, gateway int) error {
	if !filepath.IsAbs(vendor) || !strings.HasPrefix(filepath.Clean(exe), filepath.Clean(vendor)+"/") {
		return errors.New("the plugin executable must be inside the vendor directory")
	}
	if err := hardenHost(); err != nil {
		return err
	}
	// One directory per socket: a restarted container serves the same socket and reclaims it, and
	// two hosts never share one.
	sum := sha256.Sum256([]byte(l.Addr().String()))
	st, err := newStage(filepath.Join(os.TempDir(), "plughost-"+hex.EncodeToString(sum[:8])))
	if err != nil {
		return fmt.Errorf("the plugin host stages the verified plugin under %s, which must be writable (an emptyDir): %w", os.TempDir(), err)
	}
	if err := checkMemoryBacked(st.dir); err != nil {
		return err
	}
	slots := make(chan struct{}, max)
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				var once sync.Once
				release := func() { once.Do(func() { <-slots }) }
				defer release()
				if uid, err := peerUID(c); err != nil || uid != gateway {
					fmt.Fprintln(os.Stderr, "plughost: stream refused: the connecting process is not the gateway's user")
					c.Close()
					return
				}
				serve(c, exe, vendor, st, release)
			}()
		default:
			fmt.Fprintf(os.Stderr, "plughost: stream refused: %d streams already running\n", max)
			c.Close()
		}
	}
}

// serve runs one stream: the hello, then the plugin with the connection as its stdin and stdout.
// release frees the stream's slot; when the plugin ends normally it is called before the
// connection closes, so a caller that opens the next stream on seeing this one end finds the slot
// free.
func serve(c net.Conn, exe, vendor string, st *stage, release func()) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReaderSize(c, 16<<10)
	line, err := r.ReadSlice('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "plughost: stream refused: no hello line within 10 s")
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var h Hello
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&h) != nil {
		fmt.Fprintln(os.Stderr, "plughost: stream refused: the hello is not valid")
		return
	}
	args, err := h.Args(exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plughost: stream refused:", err)
		return
	}
	run, err := st.plugin(exe, h.PluginDigest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plughost:", err)
		return
	}
	args[0] = run
	// The plugin holds its service token; it must not hand it to the caller. An SDK connector
	// redacts it; any plugin's output is checked here too (scrubCopy).
	snap, token, err := snapshotToken(st.dir, h.TokenPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plughost:", err)
		return
	}
	defer os.Remove(snap)
	forms := newTokenForms(token)
	for i, a := range args {
		if strings.HasPrefix(a, "--token-file=") {
			args[i] = "--token-file=" + snap
		}
	}
	if err := CheckCores(); err != nil { // the node may have changed since the host started
		fmt.Fprintln(os.Stderr, "plughost:", err)
		return
	}
	// The plugin starts through this host's own executable (Shim), which sandboxes it before
	// running it: it cannot write the filesystem, so it cannot replace its socket or leave code
	// for a later stream.
	fail := func(err error) { fmt.Fprintln(os.Stderr, "plughost: the plugin could not be started:", err) }
	self, err := os.Executable()
	if err != nil {
		fail(err)
		return
	}
	// Its only way out: a socket carried to the profile's base URL host and port, and no further.
	target, err := egressTarget(h.BaseURL)
	if err != nil {
		fail(err)
		return
	}
	eh, ep, err := egressPair()
	if err != nil {
		fail(err)
		return
	}
	defer eh.Close()
	defer ep.Close() // closed early once the plugin holds it; this covers every refusal before that
	ectx, ecancel := context.WithCancel(context.Background())
	defer ecancel()
	go serveEgress(ectx, eh, target, filepath.Base(exe))
	cmd := exec.Command(self, append([]string{shimFlagName}, args...)...)
	// The plugin cannot read the vendor image (the unverified executable's directory) or the
	// mounted token's directory: it runs from the verified copy and reads the stream's snapshot.
	hide, err := hiddenDirs(st.dir, vendor, h.TokenPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plughost:", err)
		return
	}
	reads := snap
	if h.CAPath != "" {
		ca, err := snapshotCA(st.dir, h.CAPath, h.TokenPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "plughost:", err)
			return
		}
		defer os.Remove(ca)
		reads += ":" + ca
		for i, a := range cmd.Args {
			if strings.HasPrefix(a, "--ca-file=") {
				cmd.Args[i] = "--ca-file=" + ca
			}
		}
	}
	cmd.Env = []string{EgressFDEnv + "=" + strconv.Itoa(egressFD), HideEnv + "=" + hide, ReadEnv + "=" + reads}
	cmd.ExtraFiles = []*os.File{ep}
	cmd.Stderr = nil // can hold service content; goes nowhere
	// Its own process group, so teardown reaches the children it starts too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Both pipes are made here, each end closed by a defer at creation: exec's own pipe helpers
	// would leave the child's end of the first open if making the second failed.
	inR, in, err := osPipe()
	if err != nil {
		fail(err)
		return
	}
	defer inR.Close()
	defer in.Close()
	out, outW, err := osPipe()
	if err != nil {
		fail(err)
		return
	}
	defer out.Close()
	defer outW.Close()
	cmd.Stdin, cmd.Stdout = inR, outW
	err = cmd.Start()
	ep.Close() // the plugin holds its ends now; the host keeps only its own
	inR.Close()
	outW.Close()
	if err != nil {
		fail(err)
		return
	}
	// Teardown kills the plugin's process group and closes both pipes and the connection, so
	// neither copy below can stay blocked: not on a plugin that stops reading, a child (even one
	// that left the group) still holding the output open, or a client that stops reading.
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill() // the leader itself, wherever its group is
			_ = in.Close()
			_ = out.Close()
			_ = eh.Close()
			ecancel() // and an egress dial in flight ends with the stream
		})
	}
	teardown := func() {
		stop()
		_ = c.Close() // a client that stopped reading cannot hold the output copy either
	}
	// The connection is read whether or not the plugin reads its input, so its end is always seen:
	// then the plugin has Grace to finish its answers. Input the plugin leaves unread past MaxPending
	// ends the stream.
	pending := make(chan []byte, MaxPending/chunk)
	go func() {
		for b := range pending {
			if _, err := in.Write(b); err != nil {
				teardown()
			}
		}
		_ = in.Close()
	}()
	go func() {
		defer time.AfterFunc(Grace, teardown)
		defer close(pending)
		for {
			b := make([]byte, chunk)
			n, err := r.Read(b)
			if n > 0 {
				select {
				case pending <- b[:n]:
				default:
					teardown()
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	if err := scrubCopy(c, out, forms); errors.Is(err, ErrTokenInOutput) || errors.Is(err, ErrLineTooLong) || errors.Is(err, ErrBadFrame) {
		fmt.Fprintln(os.Stderr, "plughost:", err)
	}
	// All of the plugin's output has been passed on (or the stream refused). Stop it, reap it and
	// free the slot before the connection closes (deferred above).
	stop()
	if err := cmd.Wait(); err != nil {
		// The plugin's stderr is discarded and its exit status is its own choice, so neither is
		// logged: one fixed line says it did not exit cleanly. A call off the seccomp allow-list
		// fails with EPERM and leaves no record anywhere; see the connector deploy notes,
		// "connector fails with EPERM", for the strace reproduction.
		var ee *exec.ExitError
		if errors.As(err, &ee) && !killedByTeardown(ee) {
			fmt.Fprintln(os.Stderr, "plughost: plugin did not exit cleanly; if a call was refused by the sandbox (EPERM), see the connector deploy notes, \"connector fails with EPERM\"")
		}
	}
	release()
}
