# macOS Unix peer credentials: development prerequisite

`peer_darwin.go` now obtains the connected peer's effective UID from the kernel
using `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)`. It never substitutes the broker's
own UID. The broker's existing UID allowlist consumes that observation; profile
admission remains a separate requirement.

The implementation stays standard-library-only and builds with `CGO_ENABLED=0`.
`net.UnixConn.SyscallConn().Control` keeps the descriptor open during the lookup,
including protection against Go `Close`/descriptor reuse. The raw Darwin
`SYS_GETSOCKOPT` call receives a fixed 76-byte `xucred`. Returned length,
`XUCRED_VERSION`, advisory group count and the invalid-UID sentinel are checked.
A malformed or unavailable kernel observation fails closed. The implementation
uses no PID-to-process lookup, executable-name inference or caller identity field.

The ABI was checked against the installed Apple SDK headers `sys/un.h`
(`SOL_LOCAL=0`, `LOCAL_PEERCRED=1`), `sys/ucred.h` (`xucred`,
`XUCRED_VERSION=0`) and `sys/param.h` / `sys/syslimits.h` (`NGROUPS=16`). The
installed Go standard library exposes Darwin `SYS_GETSOCKOPT` and `Syscall6`;
its syscall pointer-lifetime convention is followed directly. Apple's `xucred`
header is under `__APPLE_API_UNSTABLE`: this narrow raw syscall/structure ABI
must be checked on each supported macOS release and architecture. It is not
presented as a qualified portable macOS service interface.

Production Darwin startup remains refused by `loadPolicy`. The actual local
macOS test runs the broker and connecting process as the same user. It proves a
kernel lookup and refusal behavior, **not protection from that user**, a
separately installed privileged service, executable identity, current human
presence, VM isolation, hardware measurement or ALPS qualification. Credentials
are the kernel's connection observation; they do not establish executable
provenance or refresh a connection's original identity after privilege changes.
The native VM backend and protected installation remain separate integration
work. Linux continues to use `SO_PEERCRED` unchanged.

```sh
GOWORK=off go test -race -run '^TestDarwinPeerUID' .
GOWORK=off CGO_ENABLED=0 go build -trimpath -o /private/tmp/hardened-broker-darwin .
GOWORK=off CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
  go build -trimpath -o /private/tmp/hardened-broker-darwin-amd64 .
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -o /private/tmp/hardened-broker-linux-arm64 .
```

The focused tests use actual private filesystem Unix sockets and the existing
broker request authorization gate. They check both connected ends, a refused
unassigned UID, closed/non-Unix/nil connections, kernel refusal for invalid,
unconnected and nonsocket descriptors, malformed credential layouts, and the
unchanged production startup refusal. Darwin amd64 cross-compilation is not an
execution result. The existing Linux `peer-uat` runs a disposable cached-image
fixture with broker UID 0 and connecting UID 65534, without a Docker socket or
network; see the main broker README for its scope and required fixture controls.
