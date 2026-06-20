rule Maldoc_LOLBins : maldoc
{
    meta:
        description = "References to Windows LOLBins commonly abused by maldocs"
        score = "4.0"
        author = "yarad"
        date = "2026-06-20"

    strings:
        $regsvr32   = "regsvr32" ascii nocase
        $rundll32   = "rundll32" ascii nocase
        $mshta      = "mshta" ascii nocase
        $certutil   = "certutil" ascii nocase
        $bitsadmin  = "bitsadmin" ascii nocase
        $wmic       = "wmic" ascii nocase
        $schtasks   = "schtasks" ascii nocase
        $msiexec    = "msiexec" ascii nocase
        $cscript    = "cscript" ascii nocase
        $wscript    = "wscript" ascii nocase
        $powershell = "powershell" ascii nocase
        $cmd_exe    = "cmd.exe" ascii nocase

        // Suspicious argument patterns
        $certutil_decode    = /certutil[^\n]{0,30}-decode/ ascii nocase
        $certutil_urlcache  = /certutil[^\n]{0,30}-urlcache/ ascii nocase
        $msiexec_http       = /msiexec[^\n]{0,30}\/i\s+http/ ascii nocase
        $rundll32_js        = /rundll32[^\n]{0,30}javascript:/ ascii nocase
        $bitsadmin_transfer = /bitsadmin[^\n]{0,40}\/transfer/ ascii nocase

    condition:
        3 of ($regsvr32, $rundll32, $mshta, $certutil, $bitsadmin, $wmic,
               $schtasks, $msiexec, $cscript, $wscript, $powershell, $cmd_exe)
        or any of ($certutil_decode, $certutil_urlcache, $msiexec_http,
                   $rundll32_js, $bitsadmin_transfer)
}
