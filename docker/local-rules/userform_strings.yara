rule Maldoc_UserForm_Payload : marker
{
    meta:
        description = "Suspicious strings hidden in VBA UserForm control data"
        score       = 40
        author      = "yarad"

    strings:
        $marker  = "USERFORM-STRINGS"
        $url     = /https?:\/\/[a-zA-Z0-9\-\.]{1,253}\.[a-zA-Z]{2,24}/
        $cmd     = "cmd.exe" nocase
        $ps      = "powershell" nocase
        $wscript = "wscript" nocase
        // Bare "Shell" matches PowerShell/benign captions; require an execution
        // construct (Shell( call, WScript/Application.Shell, ShellExecute).
        $shell1  = "WScript.Shell" nocase
        $shell2  = "ShellExecute" nocase
        $shell3  = /\bShell\s*\(/ nocase

    condition:
        $marker and any of ($url, $cmd, $ps, $wscript, $shell1, $shell2, $shell3)
}
