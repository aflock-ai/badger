# Native relay I/O and lifecycle checks

Run on macOS after the duplex host implementation is present:

```sh
python3 -B testifysec/vm/uat-relay-io.py --output /private/tmp/aflock-relay-io-new
```

The output directory must be new. This uses the installed Swift compiler and
Python only as engineering tools; it installs nothing and makes no provider
calls. The harness reads and hashes `host/relay.swift`, extracts its exact HTTP
parser/exchange and `RelayConnection`, and compiles those bytes with small
fixture entrypoints. It checks source and compiler hashes again afterward.
Changes to extraction boundaries fail explicitly; the harness carries no copy
of the implementation.

Twenty-four real local Unix-socket cases cover complete and chunked responses,
one-byte response fragments, early 429/503 with a partially written 1 MiB
request, malformed/oversized/truncated framing, no-response timeout, and peer
cancellation. Negative cases require their specific refusal code. The fixture
server independently checks received request bytes and confirms early denials
precede a complete request. Early denials do not increment the complete-request
counter. The peer-cancellation case closes an actual output pipe to produce
EPIPE without making a successful-delivery claim.

Three lifecycle cases compile the exact `RelayConnection` with an FD-only
fixture replacing the Virtualization framework connection holder. Real socket
shutdown tests cancellation before completion, completion before cancellation,
and the actual 30-second deadline. Deadline-induced downstream EPIPE must fail
completion. Processes, output, server reads and joins are bounded; unresolved
cleanup fails the report. Reports retain source, generated-source, compiler,
binary and log digests.

This is a macOS component UAT. It does not boot a VM, exercise virtio framing or
prove the model tool loop, signing, hardware attestation, cross-user isolation,
Windows/Linux portability, or deployment qualification. Use `uat-relay.py` and
`uat-worker-relay.py` for those separate VM transport and worker fixtures.
