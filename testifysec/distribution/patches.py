"""Export/reapply committed OpenCode changes against the exact pinned upstream tree.

Local source reconstruction only: metadata hashes do not authenticate a release.
No hooks, package installers, source scripts, network fetches or mirror pushes run.
"""
import argparse
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile


def git(repo, *args, data=None):
    environment = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    # Do not inherit Git plumbing overrides pointing outside the scratch repo.
    for key in tuple(environment):
        if key.startswith("GIT_") and key not in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"):
            del environment[key]
    return subprocess.check_output(["git", "-c", "core.hooksPath=" + os.devnull, "-c", "core.autocrlf=false",
                                    "-c", "submodule.recurse=false", "-C", str(repo), *args], input=data,
                                   env=environment, stderr=subprocess.PIPE)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checkout(upstream, commit, expected_tree, directory):
    if git(upstream, "rev-parse", commit + "^{tree}").decode().strip() != expected_tree:
        raise ValueError("upstream commit/tree does not match the independent pin")
    git(directory.parent, "clone", "--shared", "--no-checkout", "--no-hardlinks", str(upstream), str(directory))
    git(directory, "checkout", "--detach", commit)
    # Index the exact source bytes; no LFS/smudge/line-ending filters may silently
    # rewrite what the reconstruction comparison calls an identical tree.
    (directory / ".git/info/attributes").write_text("* -text -filter -ident -working-tree-encoding\n")


def replace_from_archive(directory, archive):
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        entries = tar.getmembers()
        for entry in entries:
            parts = PurePosixPath(entry.name).parts
            if not parts or entry.name.startswith("/") or any(p in ("..", ".") or p.lower() == ".git" for p in parts):
                raise ValueError("unsafe Git source archive")
            if not (entry.isdir() or entry.isfile() or entry.issym()):
                raise ValueError("unsupported source archive entry")
            if entry.issym():
                target = posixpath.normpath(posixpath.join(posixpath.dirname(entry.name), entry.linkname))
                if (entry.linkname.startswith("/") or "\\" in entry.linkname or
                        target == ".." or target.startswith("../") or
                        any(p.lower() == ".git" for p in PurePosixPath(entry.linkname).parts) or
                        any(p.lower() == ".git" for p in PurePosixPath(target).parts)):
                    raise ValueError("source symlink reaches outside the source or into Git metadata")
        for child in directory.iterdir():
            if child.name == ".git":
                continue
            if child.is_symlink() or child.is_file():
                child.unlink()
            else:
                shutil.rmtree(child)
        tar.extractall(directory, members=entries, filter="data")


def spec(revision, prefix, path=""):
    """A Git object name for path under prefix at revision; an empty prefix is the repository root."""
    inner = "/".join(part for part in (prefix, path) if part)
    return revision + ":" + inner if inner else revision + "^{tree}"


def export(upstream, repo, revision, prefix, destination):
    revision = git(repo, "rev-parse", "--verify", revision + "^{commit}").decode().strip()
    commit = git(repo, "show", spec(revision, prefix, "testifysec/upstream.commit")).decode().strip()
    tree = git(repo, "show", spec(revision, prefix, "testifysec/upstream.tree")).decode().strip()
    expected = git(repo, "rev-parse", spec(revision, prefix)).decode().strip()
    archive = git(repo, "archive", "--format=tar", spec(revision, prefix))
    destination.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="hc-patch-export-") as temporary:
        work = Path(temporary) / "tree"
        checkout(upstream, commit, tree, work)
        license_bytes = (work / "LICENSE").read_bytes()
        replace_from_archive(work, archive)
        if (work / "LICENSE").read_bytes() != license_bytes:
            raise ValueError("downstream removed or changed the pinned upstream license")
        git(work, "add", "-A", "--force", "--", ".")
        actual = git(work, "write-tree").decode().strip()
        if actual != expected:
            raise ValueError("source archive/filter changed bytes or modes; downstream Git tree mismatch")
        patch = git(work, "diff", "--cached", "--binary", "--full-index", "--no-ext-diff", commit, "--", ".")
        metadata = {
            "schema": "testifysec.opencode-patch/v1", "upstreamCommit": commit, "upstreamTree": tree,
            "downstreamRevision": revision, "downstreamTree": expected,
            "upstreamLicenseSha256": sha(license_bytes), "patchSha256": sha(patch),
            "sourceScope": prefix or ".", "authentication": "none; local reconstruction metadata only",
        }
        (destination / "opencode.patch").write_bytes(patch)
        (destination / "patch.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def reapply(upstream, package, expected_commit, expected_upstream_tree, expected_downstream_tree):
    metadata = json.loads((package / "patch.json").read_text())
    if (metadata["upstreamCommit"], metadata["upstreamTree"], metadata["downstreamTree"]) != (
            expected_commit, expected_upstream_tree, expected_downstream_tree):
        raise ValueError("patch metadata does not match independent source pins")
    patch = (package / "opencode.patch").read_bytes()
    if sha(patch) != metadata["patchSha256"]:
        raise ValueError("patch digest mismatch")
    with tempfile.TemporaryDirectory(prefix="hc-patch-reapply-") as temporary:
        work = Path(temporary) / "tree"
        checkout(upstream, expected_commit, expected_upstream_tree, work)
        license_bytes = (work / "LICENSE").read_bytes()
        if sha(license_bytes) != metadata["upstreamLicenseSha256"]:
            raise ValueError("upstream license pin mismatch")
        if patch:
            git(work, "apply", "--check", "--index", "-", data=patch)
            git(work, "apply", "--index", "-", data=patch)
        actual = git(work, "write-tree").decode().strip()
        if actual != expected_downstream_tree or (work / "LICENSE").read_bytes() != license_bytes:
            raise ValueError("reconstructed source or license mismatch")
    return {"reapplied": True, "downstreamTree": actual, "upstreamCommit": expected_commit,
            "upstreamLicenseSha256": sha(license_bytes)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser("export")
    write.add_argument("--upstream", required=True, type=Path)
    write.add_argument("--repo", required=True, type=Path, help="this repository's checkout")
    write.add_argument("--revision", default="HEAD")
    write.add_argument("--prefix", default="", help="subdirectory holding the source, when it is not the repository root")
    write.add_argument("--output", required=True, type=Path)
    check = commands.add_parser("reapply")
    check.add_argument("--upstream", required=True, type=Path)
    check.add_argument("--package", required=True, type=Path)
    check.add_argument("--upstream-commit", required=True)
    check.add_argument("--upstream-tree", required=True)
    check.add_argument("--downstream-tree", required=True)
    args = parser.parse_args()
    if args.command == "export":
        print(json.dumps(export(args.upstream.resolve(), args.repo.resolve(), args.revision, args.prefix, args.output.resolve())))
    else:
        print(json.dumps(reapply(args.upstream.resolve(), args.package.resolve(), args.upstream_commit,
                                 args.upstream_tree, args.downstream_tree)))
