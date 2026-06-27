#!/bin/sh
# Verify that every third-party GitHub Action pinned by commit SHA is pinned to
# the SAME SHA in every workflow that uses it. Catches the drift class where one
# workflow (e.g. maintenance.yml) carries a stale/typo'd SHA for an action that
# ci.yml/release.yml pin correctly, so its jobs fail at action resolution before
# doing any work. Only SHA-pinned `uses:` refs (action@<40 hex>) are checked;
# tag/branch refs (action@v3) and local (./...) refs are skipped.
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
wfdir="$root/.github/workflows"
pairs="$(mktemp)"
bad="$(mktemp)"
trap 'rm -f "$pairs" "$bad"' EXIT

# Collect "action<TAB>sha" for every SHA-pinned uses: across all workflows.
for wf in "$wfdir"/*.yml "$wfdir"/*.yaml; do
    [ -f "$wf" ] || continue
    grep -oE 'uses:[[:space:]]*[A-Za-z0-9._/-]+@[0-9a-f]{40}' "$wf" \
        | sed -E 's/^uses:[[:space:]]*//' \
        | while IFS= read -r ref; do
            action="${ref%@*}"
            sha="${ref##*@}"
            printf '%s\t%s\n' "$action" "$sha" >> "$pairs"
        done
done

# Any action mapped to more than one distinct SHA is a drift.
sort -u "$pairs" | cut -f1 | sort | uniq -d | while IFS= read -r action; do
    [ -n "$action" ] || continue
    shas="$(awk -F'\t' -v a="$action" '$1==a{print $2}' "$pairs" \
        | sort -u | tr '\n' ' ')"
    echo "$action pinned to multiple SHAs: $shas" >> "$bad"
done

if [ -s "$bad" ]; then
    echo "FAIL - inconsistent pinned action SHAs across workflows:"
    sed 's/^/  /' "$bad"
    exit 1
fi
echo "ok   - every SHA-pinned action is consistent across all workflows"
echo "ALL OK"
