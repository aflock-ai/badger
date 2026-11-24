#!/bin/sh
# Copies theme.css into every Go package that embeds it (Go cannot embed a file outside the
# package). Only existing copies are refreshed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
for dir in "$here/../../portal/internal/web" "$here/../../model-broker"; do
  if [ -f "$dir/theme.css" ]; then cp "$here/theme.css" "$dir/theme.css"; fi
done
