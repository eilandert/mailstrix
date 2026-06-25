/*
  PowerShell URL-despace + base64-marker + byte-array-loader + in-memory .NET
  Assembly::Load dropper heuristic. Targets a Brazilian .NET loader family
  (meusitehostgator/casatacario) that the upstream feeds miss: the stubs are
  UTF-16LE .ps1 files under 2 KB, all 0-hit against 11872 rules in main.

  Four invariants shared by every observed sample (verified 6/6 live corpus):
    1. URL de-spacing: `.Replace(' ', '')` defeats keyword scanners on the URL
    2. base64-payload marker: literal `%base64%` prefix on the encoded payload
    3. byte-array loader: `Get-Content` path + `-split ','` + `[byte]` to
       reconstruct a .NET DLL from a local text file
    4. In-memory load: `Assembly]::Load` to execute the reconstructed DLL

  The 4-way conjunction is the FP guard: no benign PowerShell uses URL-despace
  AND a `%base64%` sentinel AND a byte-array text-file loader AND Assembly::Load
  together. Each string uses `ascii wide` because these stubs ship UTF-16LE
  (wide is mandatory or they never match -- #172 GOTCHA-2).
  No YARA backreferences, no nested unbounded quantifiers (#172/#174/#177).

  References:
    MalwareBazaar live .ps1 corpus 2026 (07fec91f, 44d1e04d, 76c69bf4,
    ac8de596, dd3df5ff, f70a8b4c -- all 0-hit before this rule)
*/

rule PS1_Despaced_Assembly_Load_Loader : powershell loader heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "PowerShell URL-despace (.Replace(' ','')) + %base64% marker + Get-Content byte-array loader + Assembly::Load -- Brazilian .NET dropper family"
        reference   = "MalwareBazaar live .ps1 corpus 2026"
        score       = "70"
    strings:
        // URL de-spacing to defeat string-match filters -- exact literal form seen
        // in all samples. `ascii wide` covers both ASCII and UTF-16LE encodings.
        $despace  = ".Replace(' ', '')" ascii wide nocase
        // Inline base64 payload marker -- literal prefix identifying the encoded
        // .NET blob passed to the loader.
        $b64mark  = "%base64%" ascii wide nocase
        // byte-array loader: Get-Content reads the local text file.
        $getcont  = "Get-Content" ascii wide nocase
        // comma-split + byte cast -- reconstructs the DLL from the text file.
        $split    = "-split ','" ascii wide nocase
        // in-memory .NET assembly execution -- the delivery primitive.
        $asmload  = "Assembly]::Load" ascii wide nocase
    condition:
        // <64KB: these stubs are <2KB; size cap keeps scanning cheap and FP-safe.
        filesize < 64KB
        and $despace
        and $b64mark
        and $getcont
        and $split
        and $asmload
}
