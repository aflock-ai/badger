#!/bin/sh
# Prints the bin directory of the Lean toolchain lean-toolchain names. With no argument it only
# looks: the toolchain must already be installed, and nothing is downloaded (pushgate's fast tests
# run it this way, on hosts whose egress is not ours to widen). With --fetch it installs a missing
# toolchain first: the release archive for this platform, by exact version, from GitHub's release
# hosts only, checked against the sha256 GitHub publishes for it before anything in it runs.
# A version bump means new digests here: any other lean-toolchain value is refused.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
version=4.34.1
[ "$(cat "$here/lean-toolchain")" = "leanprover/lean4:v$version" ] || {
  echo "toolchain.sh: lean-toolchain is not v$version; update the version and digests here" >&2
  exit 1
}
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) asset=linux sum=47bf4bbd78f70c2e9670598ab7124d92b6efb7330ff33e5fbb4030f6fd72e4e4 ;;
  Linux/aarch64 | Linux/arm64) asset=linux_aarch64 sum=fdb974c2cdb4627e090d5d4007b913e09d13c4868720fb5594e22808b3de9e37 ;;
  Darwin/arm64) asset=darwin_aarch64 sum=65f22a4f047738ec742667b3247e836a86ebf06eabc12655c3dee00637e37866 ;;
  Darwin/x86_64) asset=darwin sum=c2fee70250444e46c1106a27bddfef948d1e563eef431eaac05bb946b2f73d3a ;;
  *) echo "toolchain.sh: no pinned Lean archive for $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac
name=lean-$version-$asset
# Keyed by digest: a different archive never reuses this one's tree. root is a symlink to the
# directory the winning install unpacked into; creating it is atomic and refuses an existing one.
root=${XDG_CACHE_HOME:-$HOME/.cache}/badger-lean/$sum
bin=$root/$name/bin
if [ ! -x "$bin/lake" ]; then
  if [ "${1:-}" != --fetch ]; then
    echo "toolchain.sh: Lean $version is not installed; run 'sh $0 --fetch' once on this host" >&2
    exit 1
  fi
  command -v zstd >/dev/null 2>&1 || { echo "toolchain.sh: zstd is needed to unpack $name" >&2; exit 1; }
  mkdir -p "$(dirname "$root")"
  tmp=$(mktemp -d "$root.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  # GitHub answers with a redirect to its asset host. The redirect is read, not followed, and
  # anything but that host is refused; the download itself follows no redirect.
  url=https://github.com/leanprover/lean4/releases/download/v$version/$name.tar.zst
  asset_url=$(curl -sS --proto =https --max-redirs 0 -o /dev/null -w '%{redirect_url}' "$url")
  case "$asset_url" in
    https://release-assets.githubusercontent.com/* | https://objects.githubusercontent.com/*) ;;
    *) echo "toolchain.sh: $url redirects to an unexpected host: ${asset_url%%\?*}" >&2; exit 1 ;;
  esac
  curl -sSf --proto =https --max-redirs 0 "$asset_url" -o "$tmp/$name.tar.zst"
  # Compared as strings: macOS's sha256sum -c exits 0 when it finds no well-formed line to check.
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum <"$tmp/$name.tar.zst")
  else
    got=$(shasum -a 256 <"$tmp/$name.tar.zst")
  fi
  got=${got%% *}
  [ "$got" = "$sum" ] || { echo "toolchain.sh: $name.tar.zst has sha256 $got, not $sum" >&2; exit 1; }
  zstd -dc "$tmp/$name.tar.zst" | tar -xf - -C "$tmp"
  rm "$tmp/$name.tar.zst"
  # Publish, or lose to an install that finished first: then its tree is used and this one goes.
  # -n: an existing root (a symlink to a directory) is refused, not followed and linked into.
  if ln -sn "$tmp" "$root" 2>/dev/null; then
    trap - EXIT
  fi
fi
[ -x "$bin/lake" ] || { echo "toolchain.sh: $bin/lake is missing" >&2; exit 1; }
echo "$bin"
