#!/bin/sh
# Verify every relative link target in the contrib/ README files resolves to a
# real path. Catches the kind of dangling ../README.md left after moving the
# integrations under contrib/. Only relative (non-http, non-anchor) targets are
# checked; bare #anchors and external URLs are skipped.
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
miss="$(mktemp)"
trap 'rm -f "$miss"' EXIT

for md in "$root"/contrib/*/README.md; do
    [ -f "$md" ] || continue
    dir="$(dirname "$md")"
    # ](target) link targets, fragment stripped, URLs/anchors skipped.
    grep -oE '\]\([^)]+\)' "$md" \
        | sed -E 's/^\]\(//; s/\)$//; s/#.*$//' \
        | while IFS= read -r tgt; do
            [ -n "$tgt" ] || continue
            case "$tgt" in http://*|https://*|mailto:*) continue;; esac
            [ -e "$dir/$tgt" ] || echo "$md -> $tgt" >> "$miss"
        done
done

if [ -s "$miss" ]; then
    echo "FAIL - dangling contrib/ README links:"
    sed 's/^/  /' "$miss"
    exit 1
fi
echo "ok   - all contrib/ README relative links resolve"
echo "ALL OK"
