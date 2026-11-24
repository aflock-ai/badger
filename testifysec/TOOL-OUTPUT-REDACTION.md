# Tool Output Credential Redaction

This is a runtime display/output filter, not an instruction to the model. It does
not change command arguments, permissions, environment variables, file edits, or
other tool execution inputs. It is independent of the Requirements projection.

## Scope: best effort, not adversarial

This filter is best effort. It is built for an ordinary person who exposes a
secret by accident: `cat .env`, an environment dump, a key in a config file, a
token pasted into a URL, a log line with an `Authorization` header. It is not a
security boundary against output that was crafted to get past it, and
adversarial bypasses (escapes, splits, boundaries or encodings chosen to beat the
detector) are out of scope. A finding that only a deliberately crafted output can
trigger is not treated as a defect.

The primary control is what the agent can read at all. In the managed build that
is the compiled permission rules (deny by default, then read, edit and shell) and
the OS or VM sandbox around the commands the agent runs
(`testifysec/HARDENING.md`). Keep secret files out of the agent's reach there;
this filter only lowers the cost of a mistake that gets past those limits.

## Threat Model

In scope: credentials that appear in data flowing through tool results, shell
output, error causes and progress updates (command output, file contents,
provider responses), including the escaped, terminal-wrapped and chunk-split
forms ordinary tools produce, and a secret encoded up to two layers deep (see
below).

Out of scope: output crafted to evade the filter, and code that already runs
in-process (plugins, in-process MCP servers, Code Mode) deliberately building
objects to evade redaction, such as getters, Proxies, prototype tricks or a
credential split across fields. Such code already holds the credential and the
user's authority and can send it anywhere directly. Redaction is not a sandbox.
In the managed build those plugin paths are disabled, and that is the control for
them. The read-once snapshot and plain-data copy stay because they are cheap and
keep the data path simple to reason about; they are not a claim of coverage for
hostile code.

URL clients percent-encode whitespace and double quotes in userinfo; a literal
one ends the URL. Literal whitespace or a double quote inside a password appears
only in malformed or hand-typed text and is out of scope, because matching it
would misread ordinary prose (and JSON string boundaries) as credentials. Every
other character a URL client accepts in userinfo, including `<`, `>` and a
backtick, stays inside the URL; a test checks each printable ASCII character
against `new URL()`.

Encoded text is inspected through its decodings, at most two layers deep: a
secret encoded twice (a JSON string inside a JSON string, a percent-encoded JSON
string, a percent-encoded value encoded again) is the deepest this covers. Each
view is decoded JSON-only and in full (percent and JSON), each decode also yields
a compact form without the controls and whitespace it decoded, and each new view
is decoded once more, in any order of the two kinds. An output that would still
decode at a third layer is not inspected and is withheld whole, as past the size
bound below: a depth limit that silently stopped looking would pass the secret
through. This can withhold ordinary output too, such as a percent-encoded URL
inside a JSON string inside another.

Base64 is decoded too, up to two layers (a secret base64-encoded twice). A run of
24 or more base64 characters (standard or URL-safe) that decodes to text is
scanned like any output, and if the decoded text holds a credential the whole run
is redacted. A run that is still base64 text at a third layer withholds the output
whole, like the bounds below. Decoded text counts toward the same 16 MiB bound.
Hex is not decoded.

Prefixed key formats (the GitHub, GitLab, `sk-`, Slack, AWS, Google and npm
prefixes and `eyJ` JWTs below) match anywhere in every view, with no boundary
before the prefix. Removing something (a terminal sequence, a format character,
an encoded control dropped from a compact view) therefore cannot glue a key to
the word before it and hide it. A key-shaped run inside a longer identifier is
redacted too. Fixed-length keys (AWS, Google, npm) must still end at a boundary,
so a longer identifier that merely starts like one is kept; a removed sequence or
format character after the key counts as that boundary. `Bearer` and `Basic`
keep their word boundary because they are
English words. A removed terminal sequence or format character counts as a
boundary, including one that also sits inside the word (`status\x1b[2KBea\x1b[31mrer`
reads as `Bearer`), and where a decoded view dropped a control right after the
scheme the value is read from there.

The search is also bounded at 256 views and 16 MiB of view text. An output that
exceeds either bound is not passed through: it is redacted whole (replaced with
`[redacted]`). Ordinary output stays far below the bound (tool output is capped
at 50 KiB). Every pass over a view is a single linear scan; a test holds 1 MiB of
each pathological shape (encoded `eyJ-` runs, `%25` chains, escape storms,
URL-like runs) to a fixed time budget.

## Boundaries

OpenCode 2.0 runs every tool (built-in, plugin, MCP and Code Mode calls) through one
function, `executeTool` in `packages/core/src/tool.ts`. Redaction happens there:

- Progress updates are redacted before they are published.
- The result (`output`, `content`, `metadata`) is redacted before the plugin
  `execute.after` hook sees it, and again after the hook, so a plugin can neither read
  a recognizable credential nor reintroduce one.
- A `Tool.Error` is rebuilt with its message, cause and metadata redacted.
- Everything downstream (the session runner, durable session events, truncation and
  retained output files) receives only the redacted result.

Shell output also reaches storage and the model outside a tool result, so the shell
service redacts it at its own sinks:

- The output file is redacted per stream as it is written (see Streaming). It sits in
  the data directory, where it outlives the process (backups, session export, support
  bundles), so it never holds the raw output.
- `Shell.output` serves pages by cursor to clients and to every caller below. While
  the command's raw output is in memory (up to 1 MiB per shell, held only in memory
  and never written to disk), every read is cut from `text()` of all of it, so no
  page boundary separates a credential from its label and nothing the file had to
  withhold is lost. A stream's raw lines join that copy only once the stream has
  settled (every line given to it emitted as `text()` would read it), so a read
  between chunks never shows a line whose end has not arrived; until then, and from
  an overlong line on, the copy lags, and the withheld lines appear when the process
  ends. A stream's raw tail joins at its end only if it closes every terminal
  sequence it opened (raw or encoded); otherwise its redacted lines take its place,
  so an open title cannot swallow the other stream's lines. If reading a stream fails, its unreleased raw lines are dropped and what the
  file already shows for them (its withheld marker included) takes their place. Past 1 MiB the raw copy is dropped; its redaction at that moment
  is kept, and reads continue with the redacted file from where the file was then,
  each file page redacted whole again on the way out. Cursors run through both in
  one space, so a cursor handed out before the switch reads on without skipping.
  Redacted lines a stream had written to the file but not yet released into the
  copy (its withheld marker among them) are kept after it, so nothing is lost or
  read twice, and the cut is announced exactly once where the reads continue into
  the file. When the process ends, all of this is gone with it. The read is the authority; the per-line
  write is best effort.
- A user shell (`!` command) records its output in the durable `session.shell.ended`
  event and in a synthetic completion message; a background shell job stores its
  output in the job record and posts a synthetic notification; restart recovery posts
  a notification from that record. The output in all of these comes from
  `Shell.output`, and every shell notification's text is redacted again where it is
  built (`ShellResult.notification`). The command line is the caller's input and is
  kept as written.

The filter does not need credentials from the environment, Git configuration, a
credential store, or a remote service. Tests use invented credentials only.

## Recognized Forms

- HTTP, HTTPS, WS, WSS, FTP and SSH URL userinfo, found by parsing each candidate
  with `new URL()`. For special schemes detection follows WHATWG parsing (any run
  of `/` or `\` after the colon, userinfo to the last `@`, and tabs inside the
  scheme or its slashes ignored, as URL parsers drop them). A tab inside userinfo
  is read through the same way when the result holds a password (or, when it
  does not parse, reads as `user:password`), so
  `https://alice:secret\t@host` is redacted while prose such as
  `https://host\tbob@example` is not. This is verified differentially
  against `new URL()` in the tests. Includes username/password and token-only
  userinfo. Scheme matching is case-insensitive. RFC 3986 userinfo sub-delimiters,
  including apostrophes, are supported separately from surrounding quotation.
  Both fields are replaced with `[redacted]`; host and path are kept.
- Percent-encoded userinfo and nested JSON and percent encoding layers of a full
  URL, within the bound above. JSON `\uXXXX` escapes and escaped slashes are
  recognized in the detection view.
  Unmatched source spelling is preserved, not URL-decoded for display.
- `Bearer` and `Basic` authorization values, with case-insensitive scheme matching.
  Tabs or other controls inside the scheme word (`Bea\trer`) do not hide it. A
  scheme and its value on separate lines are out of scope: a stream reads one line
  at a time.
- Kubernetes Secrets, by shape. Their values are bare secrets, often short base64
  with no recognizable format, so in an output that declares `kind: Secret` (YAML
  or JSON, as `kubectl get secret -o yaml` or `-o json` prints it) every value
  under `data:` and `stringData:` is redacted and every key is kept, so a reader
  can still tell what the Secret holds. kubectl prints `data` before `kind`, so a
  stream holds a data block until the kind arrives and remembers a declared Secret
  for the rest of the output. In a mixed list, a ConfigMap's data values are
  redacted too.
- Docker registry config, by shape. In an output with an `"auths"` map (a
  `config.json` or a decoded `.dockerconfigjson`), the `auth`, `password`,
  `identitytoken` and `registrytoken` values are redacted and the registry names
  are kept.
- Private key blocks, in every PEM and OpenSSH variant (`RSA`, `EC`, `DSA`,
  `ENCRYPTED`, `OPENSSH`), by allowlist. A `BEGIN … PRIVATE KEY-----` marker starts
  a block, and the block is redacted to the end of the output unless it has the
  strict raw PEM shape: nothing after `BEGIN` on its line; then only PEM header
  lines (`Name: value`, printable ASCII), base64 lines (`[A-Za-z0-9+/=]`) and blank
  lines; up to an `END` line with the same label and nothing else on it. Lines may
  be indented and may end in blanks or a carriage return. A well-formed raw block
  is redacted from `BEGIN` to `END` and the text after it is kept. Anything else
  (an escaped or percent-encoded block in a JSON string or URL value, a stray byte
  in the body, a mismatched or missing `END`) runs to the end of the output. The
  cost: every field and line after an encoded key is lost too, even a well-formed
  one. A stream holds the lines after an open block until it closes or the output
  ends. Public keys and certificates are kept.
- Recognizable GitHub token prefixes (`gh[pousr]_`, `github_pat_`), GitLab
  `glpat-` tokens, `sk-` API token prefixes (including `sk-proj-` and `sk-ant-`),
  Slack `xox[baprs]-` tokens, and three-component JWT-like strings starting with
  `eyJ`. Prefixed API tokens need at least 16 characters after the prefix (20 for
  `glpat-`).
- Fixed-length AWS access key IDs (`AKIA`/`ASIA` plus 16 uppercase alphanumerics),
  Google API keys (`AIza` plus 35 characters) and npm tokens (`npm_` plus 36
  alphanumerics). AWS secret access keys have no prefix and are not detected.
- ANSI CSI formatting, OSC/DCS terminal metadata and format characters are
  removed. Other control characters (a carriage return, a NUL) are shown as a
  space, since dropping them would join the words around them; detection also
  checks the text with them removed, so one placed inside a token cannot split
  it. Tabs and newlines remain. OSC/DCS contents are never displayed, including
  when their terminators arrive in a later chunk or are written escaped
  (`%1b]...`, `\u001b]...`).
- Escaped forms are decoded for detection only: percent bytes below 0x80, whole
  valid UTF-8 sequences of percent bytes (`%E2%80%8B`, so an encoded format character
  reads like the literal one),
  `\uXXXX` (any UTF-16 unit, so an escaped format character reads like the literal
  one), `\/`, and JSON short escapes.

The filter does not blanket-replace identifiers such as `token = input.token`,
password-related source code, ordinary URL paths, or every URL query string.

Tool errors are copied without retaining original diagnostic object references.
Nesting deeper than 100 levels is not walked: each recursive copy or check (result
values, progress, error causes) replaces it with `[too deep]` (progress drops it, and
a cause too deep to check is copied rather than kept by identity). Walking it would
overflow the stack, and 20,000 nested arrays fit in well under 50 KiB of JSON.

Own data fields (including non-enumerable fields and nested causes) are sanitized;
Error prototypes and tags are preserved for error-type checks. Cycles point to
sanitized copies. Diagnostic accessors and functions are omitted rather than
retaining closures over raw responses. This does not preserve arbitrary private
class state or executable behavior on diagnostic objects.

## Streaming

The shell service (`packages/core/src/shell.ts`) writes command output to a file
that the shell tool's result points the model at, and the API serves by cursor.
That file holds only redacted output.

stdout and stderr have independent decoders and redaction buffers. Each complete
line is sanitized before it is written, so no prefix of a credential reaches the
file while a command runs. An unterminated line is held until that stream's EOF
and then written redacted; if reading a stream fails, its unfinished line is
dropped instead. A stream's unterminated last line is ended before the other
stream writes again, so lines of the two streams never join.

A line that ends inside a terminal sequence only a decoded view sees (an encoded
OSC title whose terminator follows a raw newline) is held and redacted together
with the lines after it, as `text()` reads the whole output, so a stream and a
whole-output redaction agree.

Each stream buffers at most 64 Ki UTF-16 code units per line. A longer line
withholds the rest of that stream: one line, `[output withheld after an overlong
line]`, stands in for the long line and everything after it, in the stream and in
the output file. The long line is not kept, and what it held (an unterminated
escape, the label of a credential on the next line) can change how everything
after it reads, so nothing after it is trusted. A line whose decoding passes the
view bound withholds the rest the same way. This can withhold legitimate output
after a very long line from the file; reads served from the shell's raw output in
memory show it once the process ends (see Boundaries). Complete lines of the two streams
interleave in arrival order; sub-line order is not preserved. Exit codes and
command execution are unchanged. Terminal formatting is removed from the file and
other control characters, carriage returns included, appear as spaces (see
Recognized Forms).

## Display mode

`text(input, { display: true })` adds stricter rules for untrusted remote text
shown as a label to a person or a model (the Requirements sidebar and tool), where
code readability does not matter: labelled values (`password=…`, `"token": …`,
`api_key`, `access_token`, `state` and the like), every URL query and fragment,
and an authorization scheme whose value is on the next line. Plain mode keeps
those, so code such as `password = input.password` and URLs with queries stay
readable in ordinary tool output.

## Limits

This is best effort and not a guarantee that arbitrary output contains no
secrets (see Scope). Output crafted to defeat the detector is out of scope. Unknown token
formats, unlabelled passwords, private keys outside a PEM or OpenSSH block, arbitrary binary/media attachments,
hex-encoded payloads, encodings other than JSON, percent and base64, more than
two layers of encoding, base64 runs shorter than 24 characters outside a
Kubernetes Secret, secrets split across logical
lines or independent metadata fields, and intentionally obfuscated output are not
fully covered. Literal matching examples of recognized credentials are also
redacted. A tool that writes its own files or logs before returning is outside the
managed result boundary; this filter is not a process sandbox or a universal log
scrubber. MCP server log notifications and provider-executed tools are separate
channels. Do not claim they are covered by local tool settlement.

Existing transcripts, artifacts and logs are not rewritten. Secrets already pasted
by a user, present in command inputs, or previously exposed still need rotation and
separate cleanup. This change does not inspect or rotate credentials.
