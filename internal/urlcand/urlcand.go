// Package urlcand provides shared URL candidate extraction for reputation-feed
// checkers (urlhaus, threatfox, feodo). A single Extract call replaces the
// per-checker redundant regex walk + defang copy that the old code performed
// on every buffer.
//
// The extraction logic is identical to what the old per-checker Check methods
// did inline: FindAll on the raw buffer (raw candidates), then — only when the
// cheap byte-gate fires — FindAll on the defanged copy (deobfuscated
// candidates). All raw candidates come first; deobfuscated ones follow. A
// shared budget caps the total across both passes.
package urlcand

import (
	"bytes"
	"regexp"
	"strings"
)

var urlRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>)\]}\x00-\x1f]+`)

// Candidate is one URL string extracted from a buffer.
type Candidate struct {
	Raw   string // the raw URL string as found in the buffer
	Deobf bool   // true when found only in the defanged copy
}

// hasCandidateURL is the PERF-29 cheap pre-gate run BEFORE the regexp and the
// defang materialisation. It returns true whenever the buffer could plausibly
// contain a URL candidate, and false ONLY for buffers that demonstrably cannot.
//
// Soundness (strict superset):
//
//   - Raw regexp match: urlRe requires `https?://` (case-insensitive). Every
//     such match contains the literal substring "://" (all-ASCII, no locale
//     fold needed in the byte comparison). bytes.Contains for "://" is
//     case-insensitive for this purpose because "://" has no alphabetic bytes.
//
//   - Defanged match: defang() only transforms — and can only produce a URL —
//     when bytes.ContainsAny(data, "[({xX") is true (that gate is already in
//     defang itself). Any defanged form that could become http(s):// after
//     replacement must contain at least one of those bytes (e.g. hxxp→has 'x',
//     hXXp→has 'X', [.]→has '[', (.)→has '(', {.}→has '{').
//
// Therefore: a buffer that fails BOTH checks cannot produce any candidate from
// either the raw pass or the defanged pass. The pre-gate is a strict superset
// of "has any URL candidate" and can never produce a false negative.
func hasCandidateURL(data []byte) bool {
	return bytes.Contains(data, []byte("://")) || bytes.ContainsAny(data, "[({xX")
}

// Extract extracts URL candidates from data. If maxURLs <= 0 it defaults to 64.
// Raw candidates (Deobf=false) come first; defanged candidates (Deobf=true)
// follow using the remaining budget. The total number of candidates never
// exceeds maxURLs.
//
// The extraction mirrors the semantics of the old per-checker inline loop:
// budget is decremented once per regex match (not per normalized/valid URL),
// so the same first-N matches are produced regardless of which checker
// subsequently processes them.
func Extract(data []byte, maxURLs int) []Candidate {
	if maxURLs <= 0 {
		maxURLs = 64
	}
	// PERF-29: cheap pre-gate before the regexp and defang string materialisation.
	// On a clean buffer (no "://" and no defang trigger bytes) neither the raw
	// regexp nor the defang path can produce any candidate — return early without
	// allocating anything.
	if !hasCandidateURL(data) {
		return nil
	}
	budget := maxURLs

	matches := urlRe.FindAll(data, budget)
	if len(matches) == 0 && !bytes.ContainsAny(data, "[({xX") {
		return nil
	}

	var out []Candidate
	for _, m := range matches {
		if budget <= 0 {
			break
		}
		budget--
		out = append(out, Candidate{Raw: string(m), Deobf: false})
	}

	if budget > 0 {
		if defanged := defang(data); defanged != "" {
			for _, m := range urlRe.FindAll([]byte(defanged), budget) {
				if budget <= 0 {
					break
				}
				budget--
				out = append(out, Candidate{Raw: string(m), Deobf: true})
			}
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// defang rewrites common URL obfuscations malware uses in document code back
// to a scannable form. Returns "" when nothing changed (so the caller skips a
// redundant second pass). Cheap and bounded: plain string replacement only.
func defang(data []byte) string {
	// Check on the raw bytes BEFORE materialising a string: for the common
	// no-defang case this avoids a full-buffer copy on the hot path.
	if !bytes.ContainsAny(data, "[({xX") {
		return ""
	}
	s := string(data)
	r := strings.NewReplacer(
		"hxxps", "https", "hXXps", "https", "hxxp", "http", "hXXp", "http",
		"[.]", ".", "(.)", ".", "{.}", ".",
		"[dot]", ".", "(dot)", ".", "{dot}", ".", "[DOT]", ".", " dot ", ".",
		"[:]", ":", "[://]", "://",
	)
	out := r.Replace(s)
	if out == s {
		return ""
	}
	return out
}
