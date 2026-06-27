#!/bin/sh
set -e

# Create the yarad service account (sysusers if available, else useradd).
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/yarad.conf >/dev/null 2>&1 || true
elif ! getent passwd yarad >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/yarad --no-create-home \
            --shell /usr/sbin/nologin --comment "yarad scanning daemon" yarad || true
fi

# Own the state dir.
if getent passwd yarad >/dev/null 2>&1; then
    mkdir -p /var/lib/yarad/rules /var/cache/yarad
    chown -R yarad:yarad /var/lib/yarad /var/cache/yarad
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # On an upgrade ($1 = configure <oldver>), restart the unit so the new
    # binary takes over — but only if it was already active, so a fresh install
    # stays stopped until the operator sets a token and enables it. try-restart
    # is a no-op when the unit is not running.
    if [ "$1" = configure ] && [ -n "$2" ]; then
        systemctl try-restart yarad >/dev/null 2>&1 || true
    fi
fi

# First-time install ($2 empty) prints setup hints; an upgrade stays quiet.
if [ -z "$2" ]; then
    echo "yarad installed. Fetch rules:  sudo -u yarad yarad fetch-rules -cache-dir /var/cache/yarad"
    echo "Set a token in /etc/yarad/yarad.env, then:  systemctl enable --now yarad"
fi
