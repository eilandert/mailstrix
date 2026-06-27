#!/bin/sh
# Guard the README install section against hard-coded release versions that go
# stale on the next tag (a pinned x.y.z in a download URL or apt-install line
# 404s once latest advances). Illustrative "e.g. ..." comments are allowed; an
# actual command line referencing a version-pinned .deb is not.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
readme="$(cd "$here/../.." && pwd)/README.md"

fail=0

# A download URL with a version-pinned .deb name.
if grep -nE 'releases/(latest/)?download/.*yarad(-scan)?_[0-9]+\.[0-9]+\.[0-9]+_' "$readme"; then
    echo "FAIL - hard-coded version in a release download URL (use \${VER})"; fail=1
fi

# An `apt install ./yarad_x.y.z_arch.deb` command (commented examples excluded).
if grep -nE '^[[:space:]]*sudo apt install \./yarad(-scan)?_[0-9]+\.[0-9]+\.[0-9]+_' "$readme"; then
    echo "FAIL - hard-coded version in an apt install command (use \${VER}/\${ARCH})"; fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "ok   - README install commands carry no stale pinned versions"
    echo "ALL OK"
else
    exit 1
fi
