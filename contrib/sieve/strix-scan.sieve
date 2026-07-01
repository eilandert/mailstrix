# strix-scan.sieve — quarantine a message when strixd's YARA rules match it.
#
# Project:  https://github.com/myguard-labs/mailstrix
# Write-up: https://deb.myguard.nl/articles/yara-malware-scanning-mailstrix/
#
# This runs at delivery (Dovecot LDA / LMTP) and pipes the message to the
# `strix-scan-wrapper` program (a thin shell wrapper around the CGO-free
# `strix-scan` client, which POSTs the message to a central `strixd serve`).
#
# The `execute` TEST succeeds when the program exits 0. strix-scan exits:
#   0  clean/log-only — no actionable rule matched (ALSO on canary/allowlisted
#                       hits and scanner outage: it fails open)
#   1  match          — at least one actionable YARA/feed hit fired
# so:  execute true  => clean/log-only => deliver normally
#      execute false => MATCH          => flag + quarantine
# A scanner being down therefore delivers normally — mail is never lost.
#
# Requires the Dovecot `sieve_extprograms` plugin (the `vnd.dovecot.execute`
# extension) — see README.md in this directory for the dovecot config.

require ["vnd.dovecot.execute", "fileinto", "mailbox", "imap4flags", "editheader"];

if not execute :pipe "strix-scan-wrapper" {
    # An actionable YARA/feed hit matched. Tag the message and drop it in a
    # quarantine folder instead of the inbox. Adjust to taste (reject, discard,
    # header-only, …).
    addheader "X-Yara-Scan" "MATCH";
    setflag "\\Flagged";
    fileinto :create "Junk/Yara";
    stop;
}

# Clean/log-only (or scanner unreachable): fall through to normal delivery.
addheader "X-Yara-Scan" "clean";
