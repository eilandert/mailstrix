#!/bin/sh
# fetch-rules.sh — download the public YARA rulesets baked into the yarad image.
#
# Run at image-build time (after CACHEBUST so a daily rebuild re-pulls the
# latest). Output goes to $1 (default /rules). Each source is fetched into its
# own subtree, then the *.yar/*.yara files we want are flattened into the rules
# dir. A source that 404s or yields no rules is fatal (the build must not
# silently ship fewer rules), unless YARAD_RULES_OPTIONAL=1.
#
# Sources (override with env to pin a tag/commit):
#   YARAFORGE_URL  — YARA-Forge "core" packaged ruleset (single .yar bundle)
#   SIGBASE_REF    — Neo23x0/signature-base git ref (default master)
#   ANYRUN_REF     — anyrun/YARA git ref (default main); ANYRUN=0 to skip
set -eu

OUT="${1:-/rules}"
mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "fetch-rules: $*" >&2; [ "${YARAD_RULES_OPTIONAL:-0}" = "1" ] || exit 1; }

# 1) YARA-Forge core bundle — one curated .yar of vetted public rules.
YARAFORGE_URL="${YARAFORGE_URL:-https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip}"
echo "fetch-rules: YARA-Forge core <- $YARAFORGE_URL"
if curl -fsSL "$YARAFORGE_URL" -o "$TMP/forge.zip"; then
    unzip -o -q "$TMP/forge.zip" -d "$TMP/forge" || fail "unzip yara-forge failed"
    find "$TMP/forge" \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
        cp "$f" "$OUT/yaraforge-$(basename "$f")"
    done
else
    fail "download yara-forge failed"
fi

# 2) Neo23x0 signature-base — broad community malware/phishing rules.
SIGBASE_REF="${SIGBASE_REF:-master}"
echo "fetch-rules: signature-base <- Neo23x0@$SIGBASE_REF"
if curl -fsSL "https://github.com/Neo23x0/signature-base/archive/${SIGBASE_REF}.tar.gz" -o "$TMP/sigbase.tgz"; then
    tar -xzf "$TMP/sigbase.tgz" -C "$TMP"
    # Only the yara/ subtree; skip rules that reference external modules we
    # don't load (cuckoo/androguard) by leaving those to compile-time pruning.
    find "$TMP"/signature-base-*/yara \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
        cp "$f" "$OUT/sigbase-$(basename "$f")"
    done
else
    fail "download signature-base failed"
fi

# 3) ANY.RUN — actively maintained malware-family + phishing rules (repo root).
#    Mail-relevant (html_phishing_campaign, corrupted_docs, loader families).
if [ "${ANYRUN:-1}" = "1" ]; then
    ANYRUN_REF="${ANYRUN_REF:-main}"
    echo "fetch-rules: anyrun <- anyrun/YARA@$ANYRUN_REF"
    if curl -fsSL "https://github.com/anyrun/YARA/archive/${ANYRUN_REF}.tar.gz" -o "$TMP/anyrun.tgz"; then
        tar -xzf "$TMP/anyrun.tgz" -C "$TMP"
        find "$TMP"/YARA-* \( -name '*.yar' -o -name '*.yara' \) | while read -r f; do
            cp "$f" "$OUT/anyrun-$(basename "$f")"
        done
    else
        fail "download anyrun failed"
    fi
fi

COUNT="$(find "$OUT" -name '*.yar' -o -name '*.yara' | wc -l)"
echo "fetch-rules: $COUNT rule files in $OUT"
[ "$COUNT" -gt 0 ] || fail "no rule files fetched"
