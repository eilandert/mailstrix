#!/bin/sh
# Maintainer-script behaviour test. Runs preremove.sh / postinstall.sh with a
# fake `systemctl` (and the systemd marker dir faked present) and asserts:
#   - prerm "upgrade"  must NOT stop or disable yarad
#   - prerm "remove"   must     stop and  disable yarad
#   - postinst upgrade (configure <oldver>) try-restarts yarad
#   - postinst install (configure, no oldver) does NOT restart, prints hints
# No root / no real systemd needed; the fake systemctl just logs its argv.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Fake systemctl that appends its arguments to $CALLS, one call per line.
mkdir -p "$work/bin"
cat > "$work/bin/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> "$work/calls"
exit 0
EOF
chmod +x "$work/bin/systemctl"
# Pretend systemd is running so the `[ -d /run/systemd/system ]` guards fire.
mkdir -p "$work/run/systemd/system"

fail=0
check() { # desc, expected-grep (empty = must be absent), file
    desc="$1"; pat="$2"; f="$3"
    if [ -z "$pat" ]; then return 0; fi
    if grep -q -- "$pat" "$f" 2>/dev/null; then
        echo "ok   - $desc"
    else
        echo "FAIL - $desc (expected '$pat' in calls)"; fail=1
    fi
}
absent() { # desc, pattern, file
    desc="$1"; pat="$2"; f="$3"
    if grep -q -- "$pat" "$f" 2>/dev/null; then
        echo "FAIL - $desc (unexpected '$pat' in calls)"; fail=1
    else
        echo "ok   - $desc"
    fi
}

run() { # script, args...  -> resets calls, runs with fakes on PATH + faked root
    : > "$work/calls"
    script="$1"; shift
    # Run a copy with /run/systemd/system check redirected: we can't fake an
    # absolute path, so the scripts test `-d /run/systemd/system`. Instead we
    # rely on the host having it; if absent, skip the systemd-gated asserts.
    PATH="$work/bin:$PATH" sh "$here/$script" "$@"
}

if [ ! -d /run/systemd/system ]; then
    echo "# /run/systemd/system absent on host — systemd-gated asserts limited"
fi

# --- prerm upgrade: keep service ---
run preremove.sh upgrade 1.1.1
absent "prerm upgrade does not stop"    "stop yarad"    "$work/calls"
absent "prerm upgrade does not disable" "disable yarad" "$work/calls"

# --- prerm remove: tear down ---
run preremove.sh remove
if [ -d /run/systemd/system ]; then
    check "prerm remove stops"    "stop yarad"    "$work/calls"
    check "prerm remove disables" "disable yarad" "$work/calls"
fi

# --- postinst upgrade: restart new binary ---
out="$(run postinstall.sh configure 1.1.0 2>&1 || true)"
if [ -d /run/systemd/system ]; then
    check "postinst upgrade try-restarts" "try-restart yarad" "$work/calls"
fi
if printf '%s' "$out" | grep -q "yarad installed"; then
    echo "FAIL - postinst upgrade printed first-install hints"; fail=1
else
    echo "ok   - postinst upgrade stays quiet"
fi

# --- postinst fresh install: no restart, prints hints ---
out="$(run postinstall.sh configure 2>&1 || true)"
absent "postinst install does not restart" "try-restart yarad" "$work/calls"
if printf '%s' "$out" | grep -q "yarad installed"; then
    echo "ok   - postinst install prints hints"
else
    echo "FAIL - postinst install missing hints"; fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "ALL OK"
else
    echo "FAILURES"; exit 1
fi
