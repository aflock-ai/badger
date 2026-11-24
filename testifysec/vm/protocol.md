# Developer VM job channel, version 2

The read-only root image contains PID1 and any pinned worker/toolpack files. It
contains no session job. `hc-vm CONFIG` reads a private, regular, single-link
configuration of at most 4 KiB, then the exact private job bytes of at most
32 KiB. Each run creates a fresh random 128-bit boot nonce. There is no runtime
filesystem-image creation, package installation, Docker invocation or additional
executable needed by this host launcher.

The host exposes one listener on the VM's virtio socket device, port **17001**.
PID1 connects to host CID **2** at that fixed port, with bounded retries. The
host accepts one connection; a second is refused and stops the VM. It does not
connect the VM to TCP/IP, proxy arbitrary ports, attach a NIC or share a host
directory. Port **17002** is enabled only when the trusted developer configuration
includes both `gatewayConfigFile` and `gatewayConfigSha256`. This optional relay
is specified below; it is not a general network proxy.

The host sends one binary frame:

```text
HCJOB2\r\n | uint32 big-endian envelope length | UTF-8 JSON envelope | EOF
```

The envelope is at most 64 KiB and has exactly `schema`, `nonce`, `jobBase64`.
Its schema is `testifysec.vm-envelope/v2`; base64 must be canonical. The decoded
job is bounded at 32 KiB. EOF is required immediately after that frame, before
installing materials or starting the worker. Truncation, excess bytes, a second
frame, invalid lengths, duplicate/unknown/aliased JSON fields, null fields,
invalid assignments and missing EOF fail closed. Guest reads have both socket
operation timeouts and a five-second absolute shutdown deadline; the host's
independent overall deadline stops the VM even if guest code stops responding.

The host's boot command line binds the fresh nonce, exact job SHA-256 and this
tuple: `requestSha256`, `profileSha256`, `sessionId`, `materialsSha256`,
`backendSha256`. The frame nonce must match those boot expectations; replaying
an exact prior boot's frame under a new nonce is refused. This is freshness
within a host-created boot, **not a persistent cross-boot request ledger**. A
trusted caller may deliberately submit the same request as a new session; live
policy/replay authorization is a later broker integration responsibility.

The job has schema `testifysec.vm-job/v2`, that exact `binding`, a `request`
object with `mode` and `prompt`, and a `materials` array. Request and materials
digests hash their exact nested JSON value bytes as carried in the job, not a
second serialization. Backend digest is SHA-256 of lowercase kernel digest,
newline, lowercase root-disk digest, newline. The host independently checks
those input-file digests. These are development input bindings, **not runtime
measurements, signed profile admission or hardware attestation**. Profile digest
and session identity are configured fixture values; this layer authenticates
neither a platform agent nor a current user.

Modes remain fixed compiled development workloads (`edit`, `timeout`, `overflow`,
`symlink`, `descendant`, `worker`, `gateway`). No caller-selected executable, shell command,
host path or mount is accepted. Prompt is bounded to 4096 UTF-8 bytes. Worker
mode passes it and the bound profile digest through the existing worker stdin
protocol. The pinned worker build manifest distinguishes an embedded fixture
model from a gateway-mode worker; gateway mode uses the optional fixed relay.
Neither choice adds signed VM admission. Materials contain exactly `path`,
`contentBase64`, `sha256`: at most 16 flat ASCII names, each at most 128 bytes,
8 KiB per file and 16 KiB total. Path traversal, `.git` case variants, duplicate
case-folded names and mismatched/noncanonical bytes are refused. Files are
created exclusively on the bounded workspace tmpfs and owned by UID/GID 65534.

The output-only virtio console remains the result channel:

```text
HCVM1 <eight hexadecimal length bytes> <UTF-8 JSON result>\n
```

Its result schema is now `testifysec.vm-result/v2`; the host observation schema
is `testifysec.vm-observation/v2`. The host requires the exact boot nonce, job
digest, complete assignment tuple and PID1. `jobValidated:true` is set only after
the guest independently hashes and validates the received job and materials;
failure results retain expected binding fields with `jobValidated:false`.
Success additionally requires the actual VZ running/stopped lifecycle. Guest
messages are unsigned and do not prove the guest kernel's trustworthiness.

Result JSON is limited to 64 KiB, total console output to 256 KiB, worker output
to 32 KiB. Capture occurs after killing/reaping the entire workload, including
descendants that changed groups. It retains at most 16 single-link regular
files, 8 KiB each and 16 KiB total, as base64 bytes. No host extraction/application
is performed. Kernel log diagnostics retain only a bounded 4 KiB tail. Host
shutdown also shuts the transport down and bounds its drain before release.

The separate **hc-vm-uat** executable compiles fixed transport faults under
`HC_VM_PROTOCOL_UAT` for real VM negative tests: exact prior nonce replay,
duplicate frame, overlong frame, truncation and missing EOF. The normal hc-vm
binary rejects those configuration fields. Neither executable is a qualified
release. Old v1 baked-job configurations are explicitly refused; there is no
fallback to the prior channel or to host execution.

## Fixed model relay

The optional host configuration pins the exact private native gateway config
bytes and requires their `session` and `profileDigest` to match the VM binding.
The gateway socket destination comes from those host-only bytes. Before each
connection the host rechecks that digest, the socket's owner/type and private,
canonical parent, and kernel peer UID after connecting. Nonblocking Unix connect
has a three-second deadline. This fixture assumes developer-owned inputs and
does not protect against a malicious same-user process replacing the entire
configuration/service, or establish production ancestor/install custody.

PID1 mounts a 1 MiB `/run` tmpfs and creates the root-owned directory and socket
`/run/hardened-gateway/gateway.sock`. The untrusted worker can connect but cannot
replace the directory/socket. Only POST to `/v1/chat/completions` or
`/v1/responses`, without query/encoded path/content encoding, is accepted. The
native gateway independently enforces its one configured protocol and exact
model; allowing two transport routes does not grant both provider protocols.
No worker HTTP header is forwarded as authority.

Model transport version 2 uses a bounded receipt and acceptance exchange. The
request JSON envelope remains `testifysec.vm-model-request/v1`; its fields and
assignment meaning are unchanged. The previous `HCMDL1` framing is refused.

```text
guest -> host: HCMDL2\r\n | uint32 big-endian length | UTF-8 JSON envelope
host -> guest: HCRCP2\r\n | SHA-256(exact complete request frame), 32 raw bytes
guest -> host: HCCMT2\r\n | SHA-256(exact 40-byte receipt), 32 raw bytes | EOF
host -> guest: gateway HTTP response
```

The host sends the fixed 40-byte receipt only after reading the complete bounded
frame. The guest verifies its magic and exact frame digest before sending the
fixed 40-byte acceptance marker and shutting down its write side. The host requires
that exact marker and strict EOF before validating the envelope, assignment and
sequence and connecting to the gateway. A missing, short or incorrect receipt
causes the guest to close without acceptance; that close cannot satisfy the host's
marker requirement. Receipt and acceptance describe transport handoff only, not
authorization, identity, policy approval or model success. After valid acceptance,
subsequent cancellation can race a provider effect. Bytes after the fixed receipt
belong to the HTTP response; this protocol does not claim to detect every malicious
host response before an effect.

This exchange addresses an observed local compatibility failure: a roughly
26 KiB frame reached the host promptly, while EOF arrived only after the guest's
receive timeout closed the socket. The staged native HTTP fixture independently
reproduced that behavior without OpenCode. No vendor root cause is asserted. The
receipt exchange keeps the strict EOF gate and existing deadlines; it does not
replace them with a delay or timeout increase.

The envelope has exactly `schema: "testifysec.vm-model-request/v1"`, `nonce`,
`jobSha256`, `binding`, integer `sequence`, `path` and canonical `bodyBase64`.
The frame is at most 1,400,000 bytes and the decoded body at most 1 MiB. The host
rejects duplicate/unknown/null fields, invalid encodings, incomplete/trailing
frames and every mismatch against its fresh nonce, pinned job and complete
assignment tuple before connecting to the gateway. Sequence values 1..32 can be
used once each per VM; exact replay is refused. The guest reserves its two
in-flight slots before reading any HTTP body or attempting a connection. Pending
connects are nonblocking, check cancellation on a 50ms poll and have a 2.5-second
deadline. There are at most 32 accepted host connections and two active host
transports. These bounds belong to one live VM, not
a persisted cross-boot replay ledger or platform agent identity proof. A hostile
worker may use its VM's allowed model capability; knowledge of boot bindings is
not claimed as a secret or privilege separation from that worker.

The host reconstructs only POST, fixed Host, JSON Content-Type, exact body length
and Connection: close headers. The gateway continues to own provider credentials,
signed profile checks, live platform checks when configured, durable audit before
effect and protocol validation. The response returns as the gateway's original
HTTP bytes, bounded to 16 MiB plus 64 KiB framing overhead. The guest HTTP adapter
retains only Content-Type, Cache-Control and the gateway request ID, limits body
output to 16 MiB, and aborts a partial chunked response on truncation. Neither a
relay EOF nor `forwarded` count is a model success claim. Responses terminal
semantics remain enforced by the native gateway; partial intermediate output can
have been delivered before a later protocol failure.

The host writes the fixed gateway request while reading its response, so an early
HTTP refusal such as 429 need not terminate the entire VM. Request-write failure
is not treated as a complete exchange unless the bounded parser observes a
complete HTTP 400–599 refusal. The additive diagnostic counters retain the
`testifysec.vm-observation/v2` schema: `forwarded` counts requests whose entire
header and body were written; `earlyGatewayRefusals` counts complete 400–599
exchanges where that write remained incomplete; `responseCancellations` counts
recognized response-side peer closes. A refusal received early whose request
write subsequently completes is counted as `forwarded`. None of these counters
asserts complete response delivery or successful model execution. A host deadline
or shutdown must remain an error, not a benign peer-cancellation count.

Socket operations have three-second host idle bounds and each accepted relay
has a 30-second absolute deadline. The VM's independent overall deadline still
applies. Shutdown fences listener admission on the VM queue, interrupts every
registered transport, drains it within four seconds and requires observed VM
stop. A relay error is a failed VM run; there is no host execution fallback.
The native synthetic `gateway` workload includes raw-frame attack cases for UAT.
No test mode confers production admission; production guards remain unchanged.
