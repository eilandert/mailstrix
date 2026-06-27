#!/bin/sh
set -e

# dpkg calls prerm with "upgrade <newver>" before unpacking a replacement and
# with "remove" (or "remove in-favour ...") on an actual removal. Only stop and
# disable the service when the package is really going away — on an upgrade the
# old unit must keep running until postinst restarts it with the new binary,
# otherwise a routine `apt upgrade` would silently leave the scanner down and
# disabled.
case "$1" in
    remove|deconfigure)
        if [ -d /run/systemd/system ]; then
            systemctl stop yarad >/dev/null 2>&1 || true
            systemctl disable yarad >/dev/null 2>&1 || true
        fi
        ;;
    upgrade|failed-upgrade)
        # keep the running service; postinst restarts it after the new unpack
        ;;
esac
