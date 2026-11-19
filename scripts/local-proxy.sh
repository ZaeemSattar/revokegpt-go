#!/bin/sh
# Serves this checkout's core module as github.com/ZaeemSattar/revokegpt-go@v<version> from a file:// module proxy, so the
# firewall module can be built the way a release builds them (no go.work, the core fetched by version) before
# the core tag exists. Used by the release workflow's dry run; a real release uses the real proxy.
# Usage: scripts/local-proxy.sh <version> <proxy-dir>      then: GOPROXY=file://<proxy-dir>,https://proxy.golang.org GOSUMDB=off
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <version, e.g. 0.1.0> <proxy-dir>" >&2; exit 2; }
version=$1
proxy=$2
module=github.com/ZaeemSattar/revokegpt-go
here=$(cd "$(dirname "$0")/.." && pwd)
dir="$proxy/$module/@v"
mkdir -p "$dir"
printf 'v%s\n' "$version" > "$dir/list"
printf '{"Version":"v%s","Time":"2026-01-01T00:00:00Z"}\n' "$version" > "$dir/v$version.info"
cp "$here/go.mod" "$dir/v$version.mod"
python3 - "$here" "$dir/v$version.zip" "$module@v$version" <<'PY'
import os
import sys
import zipfile

root, out, prefix = sys.argv[1:4]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for base, dirs, files in os.walk(root):
        # What the module proxy leaves out: nested modules, VCS metadata, vendor directories.
        dirs[:] = sorted(d for d in dirs if d not in (".git", "vendor") and not os.path.exists(os.path.join(base, d, "go.mod")))
        for f in sorted(files):
            path = os.path.join(base, f)
            z.write(path, prefix + "/" + os.path.relpath(path, root).replace(os.sep, "/"))
PY
echo "$proxy"
