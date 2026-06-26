# Mail attachment scanner comparison

Scope: tools commonly layered under rspamd / amavis / Postfix for detecting
malicious Office documents, scripts, and other attachment-borne threats.

---

## At a glance

| Dimension              | oletools                        | SA OLE plugin                   | ClamAV                             | yarad                                  |
|------------------------|---------------------------------|----------------------------------|------------------------------------|----------------------------------------|
| Type                   | Static extractor + heuristics   | Score contributor (presence)     | Signature AV                       | YARA engine + reputation feed lookups  |
| Language / runtime     | Python 3 (subprocess)           | Perl (in-process SA)             | C (clamd daemon)                   | Go + cgo/libyara (daemon)              |
| Detection basis        | VBA keyword patterns, auto-exec, obfuscation markers | Macro present (binary + OOXML) | Known-bad signatures + hashes      | YARA rules (heuristic + IOC) + feeds   |
| Pre-extraction         | VBA decompress, RTF peel, embedded object carve | Raw OLE header probe only | OLE2 unpack, ZIP (OOXML), PE sections | VBA decompress, XLM eval, URL extract, OLE stream walk, SVG/MHTML carve |
| Novel variant coverage | Medium — keyword patterns age   | Low — presence signal only       | Low — signature lag (hours–days)   | High — rules target patterns not hashes |
| Reputation feeds       | None                            | None                             | None                               | URLhaus, MalwareBazaar, ThreatFox, Feodo |
| Integration path       | CLI subprocess / milter wrapper | SA `loadplugin`                  | clamd UNIX socket / amavis         | rspamd HTTP plugin (yara.lua)          |
| Inline latency         | ~200–800 ms (Python cold start) | ~10–30 ms (in-process)           | ~10–50 ms (clamd socket)           | ~5–30 ms (Go, warm cache)              |
| Rule / sig updates     | pip release (weeks)             | Manual plugin update             | freshclam (multiple per day)       | Nightly `.yac` cron → Docker rebuild   |
| False positive risk    | Medium (keywords hit legit macros) | Low (presence-only, weak signal) | Low (precise sigs)              | Medium (heuristic YARA rules)          |
| Tuning surface         | Per-tool flags, allow-lists     | SA score weight                  | Whitelist signatures               | `SLOW_RULE_DENYLIST`, `YARAD_RULE_DENYLIST`, rspamd score weight |
| Memory footprint       | ~50 MB Python per process       | in-process SA heap               | ~30 MB clamd + ~200 MB sig DB      | ~75 MB rules RSS + feed hash sets      |
| Archive / container unpack | OLE2, ZIP, RTF, embedded objects | None                        | ZIP (OOXML), PE                    | ZIP, OLE2, RTF, encoded streams, SVG data: URIs, MHTML |

---

## Strengths

**oletools** — deepest VBA analysis available open-source. Deobfuscation, auto-exec
classification (mraptor), metadata extraction, embedded-object carving. olevba is
the ground-truth reference tool for "is this macro malicious". Best for async triage
and manual review.

**SpamAssassin OLE plugin** — zero additional infra if SA already in the stack. Useful
as a lightweight trip-wire (macro-in-attachment score bump) without running a separate
daemon. Signal is weak (presence-only); combine with higher-signal tools.

**ClamAV** — best known-bad coverage. Fast, operationally well-understood, low FP
profile. Essential for bulk signature matches (Emotet, QakBot, known Office droppers).
Freshclam keeps signatures current within hours of a new family being catalogued.

**yarad** — only tool in this set that combines pre-extraction (macros, XLM formulas,
URLs, container payloads) with heuristic YARA rules AND live reputation feed lookups
in one inline pass. Catches novel variants ClamAV misses before signatures exist.
Rules are auditable and tunable. Compiled ruleset baked into the image — no 200 MB
sig DB pulled at runtime.

---

## Weaknesses

**oletools** — Python subprocess overhead (~200–800 ms) makes synchronous inline use
at volume impractical. No reputation feeds. Keyword rules drift vs obfuscation
evolution; requires periodic rule review.

**SA OLE plugin** — presence-only: fires on every macro-containing document regardless
of content or intent. No extraction, no feeds, no YARA. Produces noise on legitimate
finance / legal macro documents. Redundant if rspamd with a real scanner is the MTA
layer.

**ClamAV** — ineffective against zero-days until a signature is published (hours to
days lag). Signatures match near-exact bytes; minor repacking, XOR, or base64 wrapping
evades. No macro pre-extraction — macros must match in compressed OLE2 form.

**yarad** — no dynamic execution (sandbox); cannot observe payload that only manifests
at runtime. YARA rules require human curation to stay effective; false positives
possible on legitimate macro-heavy templates (finance, legal, HR). No built-in
sandboxed URL fetch (ThreatFox/Feodo check is feed-based, not live).

---

## Gaps — analysed for inline adoption

### Not inline (external infra / latency / privacy)

| Tool | What it adds | Why not inline |
|------|--------------|----------------|
| **Any.run / Cuckoo / CAPE** | Dynamic sandbox — catches payloads that never fire statically | Async only; minutes of latency; mail leaves perimeter |
| **VirusTotal** | 70+ AV engines + YARA community + behaviour | Latency + mail content / header PII leakage |

Strelka (target/strelka) was originally listed here. After surveying its 80 Python
processors, the valuable ones are all portable to pure Go — see the roadmap section
below.

### Implementable inline — pure Go, no subprocess

Research verdict: every item below is feasible in-process, zero CGo except where noted.

#### Encryption / archive gaps

**Password-protected ZIP** — top evasion technique; most inline scanners are
blind to encrypted archives. Password almost always appears verbatim in the mail body
(5–10 patterns: `"password is: X"`, `"pwd: X"`, subject token, archive basename).
rspamd already raises `MIME_ENCRYPTED_ARCHIVE` (score 1.0) via `arch:is_encrypted()`
in `mime_types.lua` — the hook point for triggering decryption + scan.

Two implementation paths:
1. **yarad extension**: rspamd Lua extracts password candidates from
   `task:get_text_parts()`, sends body text + attachment bytes to yarad via a new
   request field; yarad tries candidates with `github.com/yeka/zip` (AES-256 +
   ZipCrypto, pure Go) and YARA-scans the decrypted payload. RAR/7z needs subprocess.
2. **`malunpacker`** (`github.com/daschr/malunpacker`) — Rust ICAP sidecar that
   already solves the entire problem including rspamd integration via
   `external_services`. Ready-made; lower dev cost but adds Rust runtime.

Password candidate order: body regex patterns → filename-derived (strip extension) →
subject line → static wordlist (VelvetSweatshop, infected, password, 1234, …).

- Effort path 1: medium (Lua glue + Go decryptor + scan-child pipeline + wordlist)
- Effort path 2: low (deploy malunpacker sidecar)

#### OLE/OOXML metadata signals (ExifTool equivalent)

ExifTool is a Python/Perl subprocess; the same signals come from the OLE SummaryInformation
property set, which is already parsed by `mscfb` + `msoleps` (both pure Go, no new dep).
Switching from raw ASCII carve to structured field extraction unlocks integer/filetime
fields the current carve misses.

High-signal fields:

| Field | PID | Signal |
|-------|-----|--------|
| `RevisionNumber` | 0x0009 | `"1"` or `"0"` with non-zero word-count → exploit-kit origin; organic docs usually ≥ 2 |
| `EditTime` | 0x000A | `0` (filetime zero) = never edited interactively — programmatically assembled |
| `CreateTime` == `LastSaveTime` | 0x000C / 0x000D | Diff < 1 s → bulk-generated, saved exactly once |
| `AppName` | 0x0012 | Contains `"Equation"` → Equation Editor origin (CVE-2017-11882 vector); empty or builder-tool string |
| `Template` | 0x0007 | Starts `http://`, `https://`, or `\\` → template-injection attack (remote payload pull) |
| `Author` / `LastSavedBy` | 0x0004 / 0x0008 | Generic exploit-kit defaults: `"Administrator"`, `"admin"`, `"Owner"`, `"WIN7"` etc. |
| `Language` (DocSumInfo) | PIDDSI 0x001C | LCID 1049 (Russian) or 2052 (Chinese Simplified) in nominally English org |

- Go libraries: `github.com/richardlehane/mscfb` + `github.com/richardlehane/msoleps`
- Both already transitive deps (oleparse pulls mscfb); msoleps is a direct add
- Effort: small (structured field parse + emit typed markers e.g. `OLE-META-REVISION-ZERO`, `OLE-META-TEMPLATE-INJECTION`)

#### TLSH fuzzy hashing

`github.com/glaslos/tlsh` — pure Go, v0.4.0 (Aug 2025), 149 stars, Apache-2.0.
API: `tlsh.HashBytes([]byte) (*TLSH, error)` / `t.Diff(t2) int`. Requires ≥ 256 bytes.
MalwareBazaar has a dedicated fuzzy endpoint: `query=get_tlsh&tlsh=<hash>` — MB computes
the distance server-side and returns matching samples within its internal threshold.
Distance < 30 = same family (minor variant); also present in every MB CSV export as a
column. Catches repacked variants that evade SHA256 exact match.
- Effort: medium (hash on every attachment → MB API call, same pattern as SHA256 lookup; local cache keyed by TLSH string to absorb duplicate mail runs)

#### New format/container coverage (Strelka-derived)

All pure Go, no CGo:

| Format | Go library | Signals | Priority |
|--------|-----------|---------|----------|
| **LNK files** | `github.com/parsiya/golnk` | `CommandLineArgs` (LOLBin cmd), `WorkingDir`, `MachineID` (source host) | High |
| **OneNote (.one)** | bespoke `encoding/binary` ~100 LOC | Embedded `FileDataStoreObject` carve → dropper payload extraction; CVE-2023-21716 vector | High |
| **TNEF (winmail.dat)** | `github.com/Teamwork/tnef` | Attachment extraction from Outlook TNEF wrapper; still common in corporate mail | Medium |
| **PE / ELF headers in non-PE containers** | `github.com/saferwall/pe` + stdlib `debug/elf` | MZ/ELF magic carved from PDF streams, RTF binary blobs, OLE package objects; sections entropy | Medium |
| **VSTO manifests** | `encoding/xml` (stdlib) | `codebase` URL → remote payload pull location; cert hash | Medium |
| **HTML script / data-URI extraction** | `golang.org/x/net/html` | Inline `<script>` content, `data:` URI payloads in divs — HTML smuggling detection | Medium |
| **PDF metadata + embedded files** | `github.com/pdfcpu/pdfcpu` | Author, creator, embedded file extraction, link URLs, encryption flag | Medium |
| **Base64-encoded PE in text streams** | stdlib `encoding/base64` | Scan VBA/PS1/JS text for base64 runs decoding to `MZ` — common staged-dropper pattern; trivial 15 LOC | High |

#### IOC extraction from document body text

No maintained Go IOC library exists (assafmo/xioc abandoned 2020; vertoforce/go-ioc unmaintained).
Best approach: port key regexes from iocextract directly.
High-signal for mail:

| IOC type | Signal | Notes |
|----------|--------|-------|
| Non-RFC1918 IPv4 in VBA/PS1/JS | Hardcoded C2 | Filter 10/8, 172.16-31/12, 192.168/16, 127/8, 169.254/16 |
| URL with `.exe`/`.ps1`/`.dll`/`.bat` path | Payload download | URLhaus already covers this for URLs in the mail body/headers |
| Bitcoin address (P2PKH `1...`, P2SH `3...`, Bech32 `bc1...`) | Ransom note in PDF | Very low FP rate in mail context |
| CVE ID (`CVE-\d{4}-\d{4,7}`) | Exploit doc targeting specific CVE | e.g. CVE-2017-11882 in Equation Editor lures |

Effort: low (precompiled regexes; run over already-carved stream text).

---

## Recommended stack

**Minimum:** ClamAV (known-bad, fast) + yarad (heuristic + feeds, novel variants).

**Enhanced:** add oletools as an **async** enrichment path (rspamd async DNS-style
call or Strelka side-channel) to surface olevba verdict without blocking the mail
queue. SA OLE plugin is redundant when rspamd is the MTA layer.

**Maximum coverage:** Strelka as an async enrichment bus feeding structured metadata
back to rspamd (via Redis header injection or custom header) without blocking delivery.
Cuckoo/CAPE for high-value targets in a deferred re-scan queue.

---

## What yarad does NOT replace

- ClamAV: known-bad hash/signature coverage; freshclam update velocity
- A sandbox: dynamic payload execution and C2 callback observation
- SPF / DKIM / DMARC: sender authentication (different layer entirely)
- Content policies: attachment type blocking, password-protected archive policy
