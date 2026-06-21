package extract

import (
	"bytes"
	"encoding/ascii85"
)

// PDF filter-chain prefilters (AUDIT-PDF-FILTER-CHAIN). A FlateDecode object is
// frequently wrapped in a text-armour prefilter — `/Filter [/ASCII85Decode
// /FlateDecode]` or `[/ASCIIHexDecode /FlateDecode]` — so the raw stream body is
// ASCII85/hex text, not deflate. fromPDF's inflate then fails (the body isn't
// deflate) and the hidden JavaScript is missed. Parse the stream's /Filter chain
// and decode the safe text prefilters before handing the result to the inflater;
// a prefilter-only chain (e.g. bare /ASCII85Decode) yields the cleartext directly.
//
// Only the two text-armour prefilters are handled (they are pure, bounded, and
// the common evasion). Unknown/binary filters (LZW, RunLength, DCT, JBIG2, …)
// stop the prefilter walk — the body is passed through unchanged, exactly as
// before, so nothing regresses.

// pdfStreamFilters returns the ordered /Filter names for the stream whose
// `stream` keyword is at streamPos, parsed from the stream's own dictionary in a
// bounded backward window (mirrors pdfStreamLength's window + object clip so a
// prior object's /Filter can't be mis-applied). Names are returned WITHOUT the
// leading slash (e.g. "ASCII85Decode", "FlateDecode", or the abbreviation "A85").
// Returns nil when there is no direct /Filter (absent, or an indirect reference
// that can't be resolved without the xref) — the caller then inflates the body
// as-is.
func pdfStreamFilters(b []byte, streamPos int) []string {
	const window = 512
	lo := streamPos - window
	if lo < 0 {
		lo = 0
	}
	// Blank literal strings / comments / hex strings in the search window before
	// locating /Filter (and the object-clip "obj"), so a decoy `/Filter …` or "obj"
	// hidden in a `(...)` string or `%` comment can't be picked by the context-blind
	// LastIndex and either disable prefiltering or fabricate a prefilter-only chain
	// (which would surface still-compressed bytes). The scrub preserves length, so
	// offsets map 1:1 back onto b — the real /Filter name tokens (never inside a
	// string) are still read from b. Mirrors the AUDIT-PDF-LEXER scrub rationale.
	scrub := scrubPDFWindow(b[lo:streamPos])
	if oi := bytes.LastIndex(scrub, []byte("obj")); oi >= 0 {
		scrub = scrub[oi+len("obj"):]
		lo += oi + len("obj")
	}
	rel := bytes.LastIndex(scrub, pdfNameFilter)
	if rel < 0 {
		return nil
	}
	j := lo + rel + len(pdfNameFilter)
	// Require a name boundary so "/FilterFoo" doesn't shadow "/Filter". Guard the
	// index against the full buffer (j can legitimately equal streamPos when
	// "/Filter" abuts the search window's end) — when it does, treat the missing
	// boundary as a non-match rather than skipping the check.
	if j >= len(b) || !isPDFNameTerminator(b[j]) {
		return nil
	}
	j = skipPDFWS(b, j)
	if j >= streamPos {
		return nil
	}
	// An indirect `/Filter 7 0 R` can't be resolved here — bail (inflate as-is).
	if b[j] >= '0' && b[j] <= '9' {
		return nil
	}
	var names []string
	const maxFilters = 8 // a real chain is 1–2; bound a hostile dict
	readName := func(p int) (string, int) {
		// p is at '/'. Read name-regular chars after it, decoding PDF #XX escapes
		// (PDF 7.3.5) so a hex-obfuscated filter name (/ASCII#38#35Decode →
		// /ASCII85Decode) is still recognised — otherwise it would evade prefiltering.
		p++
		var sb []byte
		for p < streamPos && !isPDFNameTerminator(b[p]) {
			if b[p] == '#' && p+2 < streamPos {
				hi := hexVal(b[p+1])
				lo := hexVal(b[p+2])
				if hi >= 0 && lo >= 0 {
					sb = append(sb, byte(hi<<4|lo)) // #nosec G115 -- hexVal is 0..15
					p += 3
					continue
				}
			}
			sb = append(sb, b[p])
			p++
		}
		return string(sb), p
	}
	switch b[j] {
	case '/':
		name, _ := readName(j)
		if name != "" {
			names = append(names, name)
		}
	case '[':
		p := j + 1
		for {
			p = skipPDFWS(b, p)
			if p >= streamPos {
				return nil // unterminated array — unresolvable, inflate body as-is
			}
			if b[p] == ']' {
				break
			}
			if b[p] != '/' {
				// A non-name element (an indirect-ref digit, garbage): the chain
				// can't be fully resolved here, so don't act on a partial view of it
				// (a trailing indirect FlateDecode/unknown would be invisible). Bail.
				return nil
			}
			var name string
			name, p = readName(p)
			if name == "" {
				return nil
			}
			names = append(names, name)
			if len(names) > maxFilters {
				return nil // implausibly long chain — hostile, bail safe
			}
		}
	default:
		return nil
	}
	return names
}

// applyPDFPrefilters decodes the LEADING text-armour prefilters (ASCII85Decode /
// ASCIIHexDecode, or their abbreviations A85 / AHx) of a /Filter chain, in order,
// and returns:
//   - out:     the decoded bytes (body unchanged if no prefilter applied);
//   - surface: true ONLY when the WHOLE chain was prefilters (a genuine
//     prefilter-only stream) so out is the final cleartext — safe to emit
//     directly. False when the walk stopped at a terminal FlateDecode or an
//     unknown/binary filter (e.g. /DCTDecode): out is then NOT cleartext and must
//     not be surfaced, only handed to the inflater.
//   - applied: true if at least one prefilter was decoded (so out != body).
//
// A nil/empty filters list returns (body, false, false).
func applyPDFPrefilters(body []byte, filters []string) (out []byte, surface, applied bool) {
	out = body
	for _, f := range filters {
		var d []byte
		switch f {
		case "ASCIIHexDecode", "AHx":
			d = decodeASCIIHexPDF(out)
		case "ASCII85Decode", "A85":
			d = decodeASCII85PDF(out)
		default:
			return out, false, applied // terminal FlateDecode/unknown — not cleartext
		}
		if len(d) == 0 {
			return out, false, applied // decode failed — keep what we have, don't surface
		}
		out = d
		applied = true
	}
	// Loop completed without hitting a terminal filter: every filter was a
	// prefilter, so out is the fully-decoded cleartext (surface) iff we decoded ≥1.
	return out, applied, applied
}

// scrubPDFWindow returns a SAME-LENGTH copy of src with PDF literal strings
// `(...)` (balanced, backslash-escape aware), comments `%…EOL`, and hex strings
// `<...>` blanked to spaces, so a decoy token hidden in one of those regions
// can't be matched by a context-blind search. Dictionary delimiters `<<`/`>>`
// are left intact (only a single `<` opens a hex string).
func scrubPDFWindow(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	n := len(out)
	i := 0
	for i < n {
		switch out[i] {
		case '(':
			// Only blank a BALANCED literal string. An unterminated '(' (no matching
			// ')' within the window) is left as an ordinary byte — blanking through to
			// the window end would erase the real /Filter that follows (an over-blank
			// evasion). Real PDFs have balanced strings; an unterminated one is
			// malformed, so leaving its bytes is the safe choice.
			if end := matchPDFString(out, i); end >= 0 {
				for ; i <= end; i++ {
					out[i] = ' '
				}
			} else {
				i++
			}
		case '%':
			for i < n && out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
				i++
			}
		case '<':
			if i+1 < n && out[i+1] == '<' { // dict open `<<` — not a hex string
				i += 2
				continue
			}
			out[i] = ' '
			i++
			for i < n && out[i] != '>' {
				out[i] = ' '
				i++
			}
			if i < n {
				out[i] = ' '
				i++
			}
		default:
			i++
		}
	}
	return out
}

// matchPDFString returns the index of the ')' that closes the literal string
// opening at `open` (which must be '('), handling nesting and backslash escapes,
// searching only within b. Returns -1 if the string is unterminated within b.
func matchPDFString(b []byte, open int) int {
	depth := 0
	for i := open; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++ // skip the escaped byte
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// decodeASCIIHexPDF decodes an /ASCIIHexDecode body: hex digit pairs, whitespace
// ignored, terminated by '>' (the EOD marker). An odd final nibble is treated as
// low-nibble zero per PDF 7.4.2. Bounded by maxBytesPerPDFStream.
func decodeASCIIHexPDF(src []byte) []byte {
	out := make([]byte, 0, len(src)/2+1)
	var hi byte
	have := false
	for _, c := range src {
		if c == '>' {
			break
		}
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			continue // whitespace / other — skip per spec
		}
		if !have {
			hi = v
			have = true
		} else {
			out = append(out, hi<<4|v)
			have = false
			if len(out) >= maxBytesPerPDFStream {
				return out
			}
		}
	}
	if have {
		out = append(out, hi<<4) // odd trailing nibble: low nibble assumed 0
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// decodeASCII85PDF decodes an /ASCII85Decode body. Tolerates an optional `<~`
// leader and stops at the `~>` EOD marker; embedded whitespace and the `z`
// all-zero shortcut are handled by encoding/ascii85. Bounded by
// maxBytesPerPDFStream (5 source chars → 4 output bytes, so the destination is
// pre-sized to the decoded ceiling and clamped).
func decodeASCII85PDF(src []byte) []byte {
	s := bytes.TrimLeft(src, " \t\r\n\f\x00")
	s = bytes.TrimPrefix(s, []byte("<~"))
	if i := bytes.Index(s, []byte("~>")); i >= 0 {
		s = s[:i]
	}
	if len(s) == 0 {
		return nil
	}
	capN := len(s)/5*4 + 8
	if capN > maxBytesPerPDFStream {
		capN = maxBytesPerPDFStream
	}
	dst := make([]byte, capN)
	ndst, _, _ := ascii85.Decode(dst, s, true) // err ignored: take what decoded
	if ndst == 0 {
		return nil
	}
	return dst[:ndst]
}
