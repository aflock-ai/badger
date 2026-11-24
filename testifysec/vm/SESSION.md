# Native VZ session integration

The local session harness joins the native session service, backend preparation,
signed profile v2 admission, a compiled OpenCode worker, the model gateway v2,
and a synthetic platform session-check endpoint
([`platform/cmd/session-platform-fixture`](../platform/cmd/session-platform-fixture/main.go))
served over local TLS with an explicitly pinned CA.
Provider replies are synthetic; no customer credential or paid model is used.
The current pinned managed worker fixes Chat Completions and model label
`approved`. This phase rejects other model/protocol assignments before backend
preparation or platform checks. Real provider-model and Responses routing requires
a coordinated worker/gateway follow-up; the relay's support for both wire routes
does not by itself make the current worker use both.

The internal service command accepts an administrator assignment and a small
request file:

```sh
vz-session --assignment /private/assignment.json --request /private/request.json
```

The request selects an assigned workspace, prompt and bounded timeout. It cannot
select an executable, backend, network endpoint, signing identity or profile.
The service snapshots the administrator's workspace, prepares byte-pinned backend
files after native signed-profile admission, creates a fresh session identifier,
and performs fresh online platform identity checks before launching the VM.
The gateway checks platform identity independently for each admitted model request.
An identity response has `authorization: "none"`; execution authority comes from
administrator policy and signed-profile admission. Enrollment AAL and delegating
user fields describe historical enrollment, without asserting current human presence.

The service generates runtime config v4 after export. Its backend manifest hash
is distinct from the existing kernel/root pair hash in the job binding. It runs
the fixed compiled host while holding prepared-file custody; no runtime ext4
builder, Python, Node, npm or Docker is involved in the session command. This is
an internal component integration, not the completed customer single-executable
distribution or a qualified cross-platform sandbox.

The native result preserves exact host observation and job bytes as base64 plus
their hashes. The nested host observation remains `admissionIntegrated:false`:
the host does not itself verify signed profiles. The service's admission and
platform identity fields are separate. Config v4 produces observation v4 with
independent serial-reader drain and observed-EOF flags; jobs and guest results
remain v3. A completed native result means observed worker exit, complete bounded
capture and confirmed cleanup. It does not establish successful model behavior
or a passing test. The harness separately checks the actual OpenCode tool events,
exit status, nested file bytes, executable flags and removals.

Run on Apple Silicon macOS with the cached build toolchain and verified retained
Linux runtime inputs:

```sh
python3 -B testifysec/vm/uat-session.py \
  --go /path/to/pinned/go \
  --bun /path/to/pinned/bun \
  --worker /private/compiled-gateway-worker \
  --worker-inputs /private/verified-linux-root-inputs \
  --output /private/tmp/avz-session-uat
```

Use a short, fresh output path to keep the session's Unix socket within Darwin's
path limit. The worker's adjacent `.manifest.json` must match both its bytes and
the selected current build inputs. The root input manifest must record the exact
regular files extracted previously. The build adds the existing clearly labeled
test-only workspace utility to exercise binary output, nested files, executable
changes, removals and unsafe output cases through a real OpenCode tool call.
That utility is part of the byte-pinned fixture disk, not a production tool claim.

The platform fixture is synthetic. Earlier versions compiled the platform's own
agent-session handler from a monorepo checkout. That handler is not available to
this repository, so the fixture now answers `POST /api/agent/session-check` itself:
one generated agent, one scoped repository, terminal revocation, and the response
shape `platformsession.Client` validates. No production enrollment store, tenant
filter or revocation store is exercised, and the harness does not need a monorepo
checkout. The harness pins the fixture's exact Go inputs before building it. The
fixture's private Unix socket only controls its synthetic state and local outage;
it is not a product endpoint. It emits no refresh credential in its observations. Each provider effect must have
one outstanding durable audit start before the request, joined by exact request
ID to its final audit record, with platform-selected agent and historical
delegator fields. Additional records must be explicit denials. Collector failures
retain the actual local spool; an offline allowance is not a claim of successful
central delivery.
For the capacity refusal, the harness waits until both permitted records are
terminal, then sends an additional credential-free fixture request on the private
gateway socket. It requires the actual audit-unavailable HTTP 503, with unchanged
record and provider-call counts. This request is labeled as a harness probe; it is
not attributed to a guest request or used as successful model execution evidence.

The matrix includes successful independent sessions, caller authority/path/timeout
overrides, duplicate input, expired and cross-version profiles, revocation and
repository-scope removal before boot, a real TLS connection outage, workspace
links, a modified backend kernel, unsupported worker routing, exhausted audit capacity, revocation between model calls,
truncated model streams, a worker deadline, and unsafe or oversized captured files.
Preboot refusals require zero host invocation and zero
provider effects. Runtime cases require observed VM stop, job/relay/serial drain,
host exit and confirmed process-group absence; no successful capture is inferred
from incomplete output. The host workspace and Git hooks are never applied or run.
Revocation remains terminal in the fixture: the mid-session revocation case
is followed by a preboot refusal against the same agent, without resetting its
revocation or replacing its credential.

Reports retain exact selected sources, native dependency manifests, built artifact
hashes, caller and generated job bindings, platform-handler observations, provider
and audit joins, and bounded process logs. They are unsigned local observations.
This phase does not provide a protected installed service identity, hardware
attestation, finalized signing evidence, host workspace application, Git push,
platform policy activation, FIPS certification or IL6 qualification. Existing
v2/v3 fixture suites and earlier preparation-only reports keep their original scope.
