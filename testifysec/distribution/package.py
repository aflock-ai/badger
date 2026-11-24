"""Package already-built artifacts. Produces an UNSIGNED manifest for a release signer."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def package(artifacts, source, output, tenant, channel, sequence, not_before, expires_at):
    output.mkdir(parents=True, exist_ok=False)
    files = []
    # The builder manifest is descriptive data, not an authenticity authority.
    # Read the actual supplied artifacts and bind the bytes into the new manifest.
    for entry in sorted(artifacts.rglob("*")):
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("artifact input contains a link or special file")
        if stat.S_ISREG(mode):
            name = "bin/" + entry.relative_to(artifacts).as_posix()
            files.append((name, entry.read_bytes(), 0o755 if mode & 0o111 else 0o644))
    if not files:
        raise ValueError("no built artifacts supplied")
    files.append(("LICENSES/OpenCode.LICENSE", (source / "LICENSE").read_bytes(), 0o644))
    inventory = []
    archive = output / "bundle.tar"
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, mode in sorted(files):
            if len(data) > 2 << 30:
                raise ValueError("artifact too large")
            header = tarfile.TarInfo(name)
            header.size, header.mode, header.mtime = len(data), mode, 0
            tar.addfile(header, io.BytesIO(data))
            inventory.append({"path": name, "sha256": sha(data), "size": len(data), "mode": mode})
    manifest = {
        "schema": "testifysec.hardened-opencode.release/v1", "product": "hardened-opencode",
        "tenant": tenant, "channel": channel, "sequence": sequence, "notBefore": not_before, "expiresAt": expires_at,
        "upstreamCommit": (source / "testifysec/upstream.commit").read_text().strip(),
        "upstreamTree": (source / "testifysec/upstream.tree").read_text().strip(),
        "archiveSha256": sha(archive.read_bytes()), "archiveSize": archive.stat().st_size, "artifacts": inventory,
    }
    (output / "manifest.unsigned.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path, help="OpenCode subtree containing preserved upstream LICENSE and pins")
    parser.add_argument("--output", required=True, type=Path, help="New output directory")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--channel", required=True)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--not-before", required=True)
    parser.add_argument("--expires-at", required=True)
    args = parser.parse_args()
    package(args.artifacts.resolve(), args.source.resolve(), args.output.resolve(), args.tenant, args.channel,
            args.sequence, args.not_before, args.expires_at)
