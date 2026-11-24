// Command probe is a stand-in connector for the launch tests: a real Go program (so it makes the
// same syscalls a connector's runtime does) that performs one behaviour, chosen by --mode, under
// the sandbox. It takes the shared connector flags like any plugin and ignores all but --mode and
// --arg.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func flagValue(name string) string {
	for _, a := range os.Args[1:] {
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v
		}
	}
	return ""
}

func main() {
	arg := flagValue("arg")
	switch flagValue("mode") {
	case "echo":
		fmt.Printf("args %s\n", strings.Join(os.Args[1:], " "))
		fmt.Printf("env %d\n", len(os.Environ()))
		fmt.Fprintln(os.Stderr, "STDERR-MARK")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			fmt.Printf("got %s\n", sc.Text())
		}
	case "hang":
		fmt.Println("up")
		time.Sleep(time.Hour)
	case "spew":
		fmt.Println("up")
		for {
			fmt.Println(strings.Repeat("x", 64))
		}
	case "truncate":
		fmt.Println("truncate:", outcome(os.Truncate(arg, 0)))
	case "signalhost":
		fmt.Println("signal:", outcome(syscall.Kill(os.Getppid(), syscall.SIGSTOP)))
	case "corelimit":
		// Not a connector built on the SDK: it reads its token (a canary) itself and never calls Main,
		// so only the host's own protections apply to it.
		if _, err := os.ReadFile(arg); err != nil {
			fmt.Println("no canary")
			return
		}
		var l syscall.Rlimit
		_ = syscall.Getrlimit(syscall.RLIMIT_CORE, &l)
		fmt.Printf("core %d %d\n", l.Cur, l.Max)
		zero := syscall.Rlimit{} // then try to lower it to 0, which would re-enable pipe dumps
		_, _, errno := syscall.RawSyscall6(syscall.SYS_PRLIMIT64, 0, syscall.RLIMIT_CORE, uintptr(unsafe.Pointer(&zero)), 0, 0, 0)
		_ = syscall.Getrlimit(syscall.RLIMIT_CORE, &l)
		fmt.Printf("lower: %s, core %d %d\n", outcome(errnoErr(errno)), l.Cur, l.Max)
	case "roots":
		// A connector's first TLS handshake loads the system roots: Go reads each certificate
		// directory and resolves the symlinks in it.
		os.Setenv("SSL_CERT_DIR", arg)
		if _, err := x509.SystemCertPool(); err != nil {
			fmt.Println("roots failed:", err)
			return
		}
		fmt.Println("roots ok")
	case "tcp":
		// A raw TCP connection of its own: the filter denies the socket call.
		c, err := net.Dial("tcp", arg)
		if err == nil {
			c.Close()
		}
		fmt.Println("tcp:", outcome(err))
	case "abstract":
		// An abstract unix socket in the pod's shared network namespace: the filter denies socket.
		c, err := net.Dial("unix", "@"+arg)
		if err == nil {
			c.Close()
		}
		fmt.Println("abstract:", outcome(err))
	case "egress":
		// The way out: ask the host on descriptor 3 for a connection; it dials the profile's host
		// and port and passes it back. The plugin names another destination as best it can (a hello
		// of its own and a CONNECT); neither chooses where the connection goes.
		f := os.NewFile(3, "egress")
		ec, err := net.FileConn(f)
		if err != nil {
			fmt.Println("egress failed:", err)
			return
		}
		u := ec.(*net.UnixConn)
		u.Write([]byte{'D'})
		b, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
		_, oobn, _, _, err := u.ReadMsgUnix(b, oob)
		if err != nil || b[0] != 'K' {
			fmt.Println("egress refused")
			return
		}
		msgs, _ := syscall.ParseSocketControlMessage(oob[:oobn])
		fds, _ := syscall.ParseUnixRights(&msgs[0])
		if flagValue("reaim") != "" {
			// Try to re-aim what it was handed at another server without connect: shut it down,
			// then send with MSG_FASTOPEN to the decoy.
			host, port, _ := net.SplitHostPort(arg)
			p, _ := strconv.Atoi(port)
			var a4 [4]byte
			copy(a4[:], net.ParseIP(host).To4())
			_ = syscall.Shutdown(fds[0], syscall.SHUT_RDWR)
			err := syscall.Sendto(fds[0], []byte("x"), 0x20000000, &syscall.SockaddrInet4{Port: p, Addr: a4})
			fmt.Printf("reaim: %v\n", err)
			return
		}
		c, err := net.FileConn(os.NewFile(uintptr(fds[0]), "conn"))
		if err != nil {
			fmt.Println("egress failed:", err)
			return
		}
		fmt.Fprintf(c, "{\"conngw\":1,\"baseUrl\":\"http://%s\"} CONNECT %s\n", arg, arg)
		line, _ := bufio.NewReader(c).ReadString('\n')
		fmt.Print("egress " + line)
	case "readproc":
		// Read /proc/<arg>/cmdline (or self, thread-self's comm); another process's is refused.
		f := "/proc/" + arg + "/cmdline"
		if arg == "thread-self" {
			f = "/proc/thread-self/comm"
		}
		if _, err := os.ReadFile(f); err != nil {
			fmt.Println("proc refused")
			return
		}
		fmt.Println("proc ok")
	case "prctl":
		// What the runtime and the SDK do: read and clear dumpability; the runtime has already named
		// its heap mappings with PR_SET_VMA (Go 1.25+), which /proc/self/maps shows when the kernel
		// supports it.
		d, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
		_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0)
		maps, _ := os.ReadFile("/proc/self/maps")
		fmt.Printf("prctl dumpable %d set %v vma %v\n", d, errno == 0, strings.Contains(string(maps), "[anon: Go: "))
	case "setname":
		// Name itself with the canary, as a plugin would to get a token into node records about it.
		name := []byte(arg + "\x00")
		_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0)
		fmt.Println("name:", outcome(errnoErr(errno)))
	case "reexec":
		// Run itself again through a descriptor of its own choosing (fd 77): the kernel names the
		// new image after the path's last element. It stays the same process, in the same sandbox.
		fmt.Printf("before pid=%d\n", os.Getpid())
		self, err := os.Open("/proc/self/exe")
		if err == nil {
			err = syscall.Dup3(int(self.Fd()), 77, 0)
		}
		if err == nil {
			err = syscall.Exec("/proc/self/fd/77", []string{"probe", "--mode=reexeced"}, nil)
		}
		fmt.Println("reexec:", outcome(err))
	case "reexeced":
		comm, _ := os.ReadFile("/proc/self/comm")
		fmt.Printf("after pid=%d comm=%s signal: %s\n", os.Getpid(), strings.TrimSpace(string(comm)), outcome(syscall.Kill(os.Getppid(), 0)))
	case "writecomm":
		// Rename itself through /proc instead: opening comm for writing is refused.
		var errs []string
		for _, f := range []string{"/proc/self/comm", "/proc/thread-self/comm"} {
			c, err := os.OpenFile(f, os.O_WRONLY, 0)
			if err == nil {
				c.Close()
			}
			errs = append(errs, fmt.Sprint(errors.Is(err, syscall.EACCES)))
		}
		fmt.Println("comm refused " + strings.Join(errs, " "))
	case "fault":
		// Put SIGSEGV back to its default action (the Go runtime installed a handler), then read a
		// fixed unmapped address. The kernel kills the process; a node with debug.exception-trace=1
		// also logs the address and registers to the kernel log.
		const addr = 0xdead0000
		var act [4]uintptr // the kernel's struct sigaction, all zero: SIG_DFL
		_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(syscall.SIGSEGV), uintptr(unsafe.Pointer(&act[0])), 0, 8, 0, 0)
		fmt.Printf("fault pid=%d at %#x reset: %s\n", os.Getpid(), addr, outcome(errnoErr(errno)))
		v := *(*byte)(unsafe.Pointer(uintptr(addr)))
		fmt.Println("no fault", v)
	case "listen":
		// A plugin that tries to be the socket server itself, as a substituted host would: it cannot
		// open a socket of its own, unix or inet, so the host stays the only listener.
		u, err := net.Listen("unix", arg)
		if err == nil {
			u.Close()
		}
		tl, terr := net.Listen("tcp", "127.0.0.1:0")
		if terr == nil {
			tl.Close()
		}
		fmt.Println("listen:", outcome(err), outcome(terr))
	case "leaktoken":
		// A plugin that skips the SDK and hands back its own token, in the form --arg names. A
		// clean line goes first; it must pass.
		b, _ := os.ReadFile(flagValue("token-file"))
		tok := strings.TrimSpace(string(b))
		fmt.Println(`{"clean":true}`)
		head := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"`
		switch arg {
		case "split": // over two writes, the second after a pause
			os.Stdout.WriteString(head + tok[:len(tok)/2])
			time.Sleep(200 * time.Millisecond)
			os.Stdout.WriteString(tok[len(tok)/2:] + `"}]}}` + "\n")
		case "base64":
			fmt.Println(head + base64.URLEncoding.EncodeToString([]byte("Bearer "+tok)) + `"}]}}`)
		case "hex":
			fmt.Println(head + strings.ToUpper(hex.EncodeToString([]byte(tok))) + `"}]}}`)
		case "none": // the control: the same lines without the token
			fmt.Println(head + "no token here" + `"}]}}`)
		case "escaped":
			fmt.Println(head + url.PathEscape("x "+tok) + `"}]}}`)
		default:
			fmt.Println(head + tok + `"}]}}`)
		}
		fmt.Println("after")
	case "tokensha":
		// Read the token file it was given, wait (the test rotates the mounted token meanwhile), read
		// it again; print a short digest of each, never the token. "ready" tells the test to rotate.
		read := func() string {
			b, err := os.ReadFile(flagValue("token-file"))
			if err != nil {
				return outcome(err)
			}
			return fmt.Sprintf("%x", sha256.Sum256(bytes.TrimSpace(b)))[:12]
		}
		first := read()
		fmt.Println("ready")
		bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Printf("sha %s %s\n", first, read())
	case "waitread":
		// Wait for the test to send ':'-separated paths, then try to read each.
		fmt.Println("ready")
		paths, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		files := strings.Split(strings.TrimSpace(paths), ":")
		ok, refused := 0, 0
		for _, f := range files {
			if _, err := os.ReadFile(f); err == nil {
				ok++
			} else {
				refused++
			}
		}
		fmt.Printf("read: %d ok %d refused\n", ok, refused)
	case "cafile":
		// Read the CA file it was given and say how many certificates it holds, and whether any
		// line is not part of a PEM block (the host gives it a re-encoded copy).
		b, err := os.ReadFile(flagValue("ca-file"))
		other := false
		in := false
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			switch {
			case strings.HasPrefix(l, "-----BEGIN "):
				in = true
			case strings.HasPrefix(l, "-----END "):
				in = false
			case !in:
				other = true
			}
		}
		fmt.Printf("ca: %s %d %v\n", outcome(err), strings.Count(string(b), "-----BEGIN CERTIFICATE-----"), other)
	case "readfile":
		_, err := os.ReadFile(arg)
		fmt.Println("read:", outcome(err))
	case "execother":
		// Replace itself with another file than its own verified copy (it cannot start a new
		// process at all): Landlock refuses executing anything else.
		fmt.Println("exec:", outcome(syscall.Exec(arg, []string{arg}, nil)))
	case "spawn":
		fmt.Println("spawn:", outcome(exec.Command("/proc/self/exe", "--mode=hang").Start()))
	case "replace":
		sock := filepath.Join(arg, "plugin.sock")
		tries := []string{
			outcome(os.Remove(sock)),
			outcome(os.WriteFile(filepath.Join(arg, "evil"), nil, 0o600)),
			outcome(os.Symlink("x", filepath.Join(arg, "link"))),
			outcome(os.Mkdir(filepath.Join(arg, "d"), 0o755)),
		}
		entries, _ := os.ReadDir(arg)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		fmt.Printf("tries %s up %s\n", strings.Join(tries, " "), strings.Join(names, " "))
	}
}

// outcome names how a call ended: ok, EPERM (the seccomp filter), EACCES (Landlock) or error.
func outcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, syscall.EPERM):
		return "EPERM"
	case errors.Is(err, syscall.EACCES):
		return "EACCES"
	}
	return "error"
}

func errnoErr(e syscall.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}
