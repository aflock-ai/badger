# jade:ring local
"""Offline release verification with real ephemeral signatures and source patch replay."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from package import package
from patches import export, git, reapply


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--artifacts", required=True, type=Path, help="Existing native builder output; never dummy binaries")
    parser.add_argument("--upstream", required=True, type=Path, help="Local upstream Git checkout holding the pinned revision")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    source = root.parents[1]
    report = {"story": "HC-07", "scope": "offline-bundle-verification-and-source-reconstruction",
              "timestamp": datetime.now(timezone.utc).isoformat(), "assertions": [],
              "sourceHashes": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()
                               if p.is_file() and p.suffix in (".go", ".py", ".mod", ".sum")},
              "revision": git(source, "rev-parse", "HEAD").decode().strip(),
              "dirtyPaths": git(source, "status", "--porcelain", "--untracked-files=all", "--", "testifysec/distribution").decode().splitlines(),
              "limitations": ["Synthetic ephemeral release authority; no production signing or publication.",
                              "Release trust is independently provisioned; verified bytes may be staged, but no activation or service installation is performed.",
                              "Minimum sequence is a provisioned floor; accepting a newer release does not persist a rollback counter.",
                              "Expiry trusts protected OS time; certificate chains, TSA evidence and revocation are not implemented.",
                              "Go runtime verifier needs no Python or package manager; packaging and UAT are build-time Python tools.",
                              "Source replay covers the recorded committed revision only, not uncommitted working files.",
                              "Native libraries, Bun and OS signing still require their separate release qualification."]}
    env = dict(os.environ, GOWORK="off", CGO_ENABLED="0", GOPROXY="off", GOSUMDB="off")
    try:
        with tempfile.TemporaryDirectory(prefix="hc-distribution-uat-") as temporary:
            work = Path(temporary).resolve()
            executable = work / "hardened-bundle-verify"
            subprocess.run([args.go, "build", "-trimpath", "-o", str(executable), "."], cwd=root, env=env, check=True)
            now = datetime.now(timezone.utc).replace(microsecond=0)
            stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
            bundle = work / "bundle"
            manifest = package(args.artifacts.resolve(), source, bundle, "synthetic-tenant", "development", 10,
                               stamp(now - timedelta(hours=1)), stamp(now + timedelta(hours=2)))
            subprocess.run([args.go, "test", "-count=1", "./..."], cwd=root,
                           env=dict(env, HC_DISTRIBUTION_FIXTURES=str(bundle)), check=True)
            runtime = {"PATH": "/nonexistent", "TMPDIR": str(work)}

            def check(name, envelope="valid", archive="bundle.tar", trust="trust.json", accepted=False, extra=()):
                result = subprocess.run([str(executable), "--trust", str(bundle / trust), "--manifest",
                                         str(bundle / (envelope + ".dsse.json")), "--archive", str(bundle / archive), *extra],
                                        env=runtime, cwd=work, capture_output=True, timeout=30)
                passed = result.returncode == (0 if accepted else 1)
                decision = None
                if accepted:
                    decision = json.loads(result.stdout)
                    passed = passed and decision.get("verified") is True and decision.get("archiveSha256") == manifest["archiveSha256"]
                else:
                    passed = passed and not result.stdout
                report["assertions"].append({"id": "HC-07." + name, "passed": bool(passed), "exitCode": result.returncode})
                if not passed:
                    raise AssertionError(name)
                return decision

            check("signed-native-bundle-without-runtime-tools", accepted=True)
            for name in ("downgrade", "wrong-tenant", "wrong-channel", "wrong-upstream", "expired", "future", "license-substitution"):
                check(name, envelope=name)
            for name in ("traversal", "symlink", "hardlink", "duplicate-entry", "extra-entry", "missing-entry", "artifact-tamper", "appended-archive"):
                check(name, envelope=name, archive=name + ".tar", trust="archive-trust.json")
            staging = work / "staging"
            staging.mkdir(mode=0o700)
            staged = check("same-bytes-native-staging", accepted=True, extra=("--stage-root", str(staging)))
            final = Path(staged["stagedDirectory"])
            assert final.parent == staging and staged["activated"] is False
            assert staged["scope"] == "offline-release-staging-only"
            paths = {p.relative_to(final).as_posix() for p in final.rglob("*") if p.is_file()}
            assert paths == {a["path"] for a in manifest["artifacts"]}
            for artifact in manifest["artifacts"]:
                value = final / artifact["path"]
                assert hashlib.sha256(value.read_bytes()).hexdigest() == artifact["sha256"]
                assert value.stat().st_mode & 0o777 == artifact["mode"]
            report["assertions"].append({"id": "HC-07.staged-exact-inventory-bytes-modes", "passed": True})
            for name in ("traversal", "symlink", "hardlink", "duplicate-entry", "extra-entry", "missing-entry", "artifact-tamper", "appended-archive"):
                before = sorted(p.name for p in staging.iterdir())
                check("stage-refuses-" + name, envelope=name, archive=name + ".tar", trust="archive-trust.json",
                      extra=("--stage-root", str(staging)))
                assert sorted(p.name for p in staging.iterdir()) == before
            report["assertions"].append({"id": "HC-07.failed-stage-cleanup-preserves-existing", "passed": True})
            public = work / "public"
            public.mkdir(mode=0o755)
            check("nonprivate-staging-root-refused", extra=("--stage-root", str(public)))
            alias = work / "staging-alias"
            alias.symlink_to(staging, target_is_directory=True)
            check("symlink-staging-root-refused", extra=("--stage-root", str(alias)))
            loose = work / "loose-parent"
            loose.mkdir(mode=0o700)
            nested = loose / "private"
            nested.mkdir(mode=0o700)
            loose.chmod(0o777)
            check("writable-staging-ancestor-refused", extra=("--stage-root", str(nested)))
            loose.chmod(0o700)
            os.mkfifo(bundle / "fifo.tar")
            check("fifo-archive-refused-without-blocking", archive="fifo.tar")
            (bundle / "archive-alias.tar").symlink_to(bundle / "bundle.tar")
            check("symlink-archive-refused", archive="archive-alias.tar")
            envelope = json.loads((bundle / "valid.dsse.json").read_text())
            claimed = json.loads(base64.b64decode(envelope["payload"]))
            claimed["sequence"] = 999
            envelope["payload"] = base64.b64encode(json.dumps(claimed).encode()).decode()
            (bundle / "manifest-tamper.dsse.json").write_text(json.dumps(envelope))
            check("manifest-tamper-cannot-self-authenticate", envelope="manifest-tamper")
            untrusted = json.loads((bundle / "trust.json").read_text())
            untrusted["purpose"] = "profile-verification"
            (bundle / "wrong-purpose.json").write_text(json.dumps(untrusted))
            check("profile-trust-purpose-refused", trust="wrong-purpose.json")
            patch_dir = work / "patch"
            meta = export(args.upstream.resolve(), source, report["revision"], "", patch_dir)
            independent_tree = git(source, "rev-parse", report["revision"] + "^{tree}").decode().strip()
            proof = reapply(args.upstream.resolve(), patch_dir, meta["upstreamCommit"], meta["upstreamTree"], independent_tree)
            report["assertions"].append({"id": "HC-07.exact-upstream-patch-replay", "passed": proof["downstreamTree"] == independent_tree})
            report["patch"] = meta
            (patch_dir / "opencode.patch").write_bytes((patch_dir / "opencode.patch").read_bytes() + b"tampered")
            refused = False
            try:
                reapply(args.upstream.resolve(), patch_dir, meta["upstreamCommit"], meta["upstreamTree"], independent_tree)
            except ValueError:
                refused = True
            report["assertions"].append({"id": "HC-07.patch-tamper-refused", "passed": refused})
            report["bundle"] = manifest
            report["verifierSha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
    current_sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()
                       if p.is_file() and p.suffix in (".go", ".py", ".mod", ".sum")}
    if current_sources != report["sourceHashes"]:
        report["failure"] = "selected source files changed while UAT was running"
    report["passed"] = bool(report["assertions"]) and all(a["passed"] for a in report["assertions"]) and "failure" not in report
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.report), "passed": report["passed"], "assertions": len(report["assertions"]), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
