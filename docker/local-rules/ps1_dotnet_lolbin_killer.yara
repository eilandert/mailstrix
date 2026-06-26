/*
  PowerShell .NET-Framework LOLBin process-killer loader.

  A RAT loader stub (AsyncRAT / DcRat family) that prepares the host for a clean
  inject by killing every process running from the .NET Framework directories and
  the specific managed LOLBins it intends to hollow into, then decrypts and runs
  its payload:

      Set-ExecutionPolicy Unrestricted -Scope Process -Force
      iwr 'http://www.google.com' -OutFile $env:USERPROFILE\Downloads\Document.pdf ; ii   # decoy
      $d = 'C:\Windows\Microsoft.NET\Framework\v2.0.50727','...\v4.0.30319'
      $n = 'mshta','msbuild','jsc','addInProcess','AddInProcess32','aspnet_compiler'
      gcim Win32_Process | ? {... ExecutablePath dir -in $d} | kill
      $n | % { kill -Name $_ -Force }
      $k = [Text.Encoding]::UTF8.GetBytes("Lulli@@@12345")   # per-sample key
      $b = ("2a%xx%x2%xf..." -replace '%','' ...)            # strip %, x->0, to bytes

  Discriminator: the conjunction of the .NET Framework install path with the
  managed-LOLBin process names `aspnet_compiler` and `AddInProcess` (the standard
  process-hollowing targets) — a benign admin script does not enumerate-and-kill
  exactly this set. Per-sample key/variable names are not keyed on.

  FP-safety: 3-way AND (Framework path + aspnet_compiler + AddInProcess) under a
  size gate. The LOLBin pair is the AsyncRAT/DcRat injection target list; no
  legitimate script kills both while referencing the Framework directory.

  Reference: MITRE ATT&CK T1055.012 (Process Hollowing), T1218 (System Binary
             Proxy Execution), T1562.001 (Disable/Modify Tools).
*/

rule PS1_DotNet_LOLBin_Killer_Loader : powershell loader heuristic malware
{
    meta:
        author      = "yarad"
        description = "PowerShell loader kills .NET Framework managed LOLBins (aspnet_compiler/AddInProcess) to prep a process inject (AsyncRAT/DcRat)"
        reference   = "https://attack.mitre.org/techniques/T1055/012/"
        sample      = "0c627ab6a8d28441c206e17807ded824d2148c3424c6a13bd7455e0c2d2d039d"
        score       = "70"
    strings:
        $fw    = "Microsoft.NET\\Framework" nocase
        $asp   = "aspnet_compiler" nocase
        $addin = "AddInProcess" nocase
    condition:
        filesize < 262144 and all of them
}
