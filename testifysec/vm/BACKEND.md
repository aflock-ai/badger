# Native VZ backend preparation

This internal preparation step packages pinned VM bytes and independently checks
an actual signed v2 profile before making a private staged copy. It does not boot
a VM or enable the existing production execution guard. Customers still target a
single Aflock executable; these build and diagnostic commands are engineering
interfaces, not a manual customer installation sequence.

`package-backend.py --build BUILD --output FRESH_DIRECTORY` copies only these
fixed local source names. It never follows paths declared inside build metadata.

| Manifest role | Installed filename | Maximum bytes |
| --- | --- | --- |
| `host` | `hc-vm` | 64 MiB |
| `kernel` | `kernel` | 128 MiB |
| `rootDisk` | `root.ext4` | 2 GiB |
| `provenance` | `build.json` | 256 KiB |

`build.json` is the original `manifest.json` from the retained build. The exporter
checks the normal `hc-vm` digest, recorded input digests and a locally present v3
build configuration. It copies and hashes each payload in the same bounded read,
then writes `backend.json` last. The session configuration, job, writable state
and fault-enabled `hc-vm-uat` are not exported. These checks establish consistency
with the supplied build record; they do not authenticate its author.

`backend.json` has schema `testifysec.aflock.vz-backend/v1`, kind `darwin-vz/v1`,
`hostTarget:darwin-arm64`, `guestTarget:linux-arm64`,
`jobSchema:testifysec.vm-job/v3`, `resultSchema:testifysec.vm-result/v3`, and
`relayProtocol:HCMDL2`. `files` has exactly the four roles above, each with exactly
`sha256` and integer `size`. Its exact raw bytes, including whitespace, determine
the manifest SHA256. The native manifest parser has a 16 KiB input bound.

The native `vz-backend-check --assignment /private/assignment.json` reads the raw
DSSE envelope from stdin. Its protected assignment names the installation,
staging parent, exact manifest and profile digests, pinned native admission
executable, and expected tenant/deployment/profile. The admission binary must
independently verify the v2 signature, assignment, sequence floor, time window
and signed backend reference. Neither request metadata nor descriptive build
provenance supplies authority to select executable paths or weaken limits.

A successful diagnostic independently reads the staged bytes, closes and cleans
the preparation, and then returns `prepared:true`, `cleaned:true` and
`executionEnabled:false`. It does not return a reusable authorization token or
promise that the staged files will be executed. The native package's future
service caller must retain custody through any later use. Exact root-disk bytes
bind its contents without pretending this verifier independently parses the
embedded guest executable, runtime or toolpack.

The exporter is a POSIX build tool. Native preparation currently targets macOS
arm64. The local harness uses current-user fixture ownership; it does not prove
isolation from processes with the same UID, an installed privileged service,
publisher signing, platform identity/revocation, hardware attestation, or
FIPS/ALPS/IL6 qualification. The retained phase-42 test root includes an explicit
UAT utility and remains a development image.

Run the offline harness from the OpenCode subtree with cached tools and the
retained actual v3 worker build:

```sh
python3 testifysec/vm/uat-backend.py \
  --build /private/tmp/retained-v3/actual-build \
  --go /absolute/path/to/go \
  --bun /absolute/path/to/bun \
  --output /private/tmp/aflock-backend-uat-NEW
```

The harness retains source, executable, manifest, fixture, decision and log
hashes. It generates ephemeral synthetic signing keys in memory, compiles actual
native profile admission, verifies signed controls and refusals, compares exact
staged bytes, and checks cleanup. It uses no customer credentials, VM boots,
Docker invocation, runtime install, live model call or public download. Native
parser/custody tests provide additional stage-specific malformed-input coverage;
a mere changed-manifest digest refusal is never labeled a successful semantic
schema test.
