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
