package extract

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

func zlibDeflate(data []byte) []byte {
	var b bytes.Buffer
	zw := zlib.NewWriter(&b)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return b.Bytes()
}

func rawDeflate(data []byte) []byte {
	var b bytes.Buffer
	fw, _ := flate.NewWriter(&b, flate.DefaultCompression)
	_, _ = fw.Write(data)
	_ = fw.Close()
	return b.Bytes()
}

// pdfWithStream wraps a single object stream body into a minimal PDF.
func pdfWithStream(body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n1 0 obj\n<< /Length 1 >>\nstream\n")
	b.Write(body)
	b.WriteString("\nendstream\nendobj\n%%EOF")
	return b.Bytes()
}

// A PDF with a FlateDecode (zlib) stream hiding JavaScript must have the inflated
// script surfaced.
func TestExtractPDFFlate(t *testing.T) {
	js := []byte("/JavaScript (app.alert('pdf dropper payload'); this.exportDataObject())")
	buf := pdfWithStream(zlibDeflate(js))
	res := Extract(buf, time.Time{})
	if !res.IsPDF {
		t.Fatal("PDF not flagged IsPDF")
	}
	if !streamsContain(res, "pdf dropper payload") {
		t.Errorf("inflated JS not surfaced; got %d streams", len(res.Streams))
	}
}

// A raw-deflate stream (no zlib wrapper) must inflate via the fallback.
func TestExtractPDFRawDeflate(t *testing.T) {
	js := []byte("OpenAction Launch raw-deflate pdf payload")
	buf := pdfWithStream(rawDeflate(js))
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "raw-deflate pdf payload") {
		t.Errorf("raw-deflate stream not surfaced; got %d streams", len(res.Streams))
	}
}

// Multiple object streams must all be inflated.
func TestExtractPDFMultipleStreams(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")
	for _, s := range [][]byte{[]byte("first pdf stream AAAA"), []byte("second pdf stream BBBB")} {
		b.WriteString("obj\nstream\n")
		b.Write(zlibDeflate(s))
		b.WriteString("\nendstream\n")
	}
	b.WriteString("%%EOF")
	res := Extract(b.Bytes(), time.Time{})
	if !streamsContain(res, "first pdf stream") || !streamsContain(res, "second pdf stream") {
		t.Errorf("not all streams inflated; got %d streams", len(res.Streams))
	}
}

// A non-deflate stream (e.g. raw image bytes) must be skipped without error.
func TestExtractPDFNonDeflateSkipped(t *testing.T) {
	buf := pdfWithStream([]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F'})
	res := Extract(buf, time.Time{})
	if !res.IsPDF {
		t.Fatal("PDF not flagged IsPDF")
	}
	if res.Panicked {
		t.Fatal("non-deflate stream panicked")
	}
}

// A truncated PDF (stream keyword but no endstream) must not panic.
func TestExtractPDFTruncated(t *testing.T) {
	buf := []byte("%PDF-1.4\nobj\nstream\n" + string(zlibDeflate([]byte("x"))))
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("truncated PDF panicked")
	}
}

// Regression (Codex #2): a stray "stream" substring (in a name/comment, not a
// real stream keyword) must NOT make the carver swallow the following real
// FlateDecode object — the genuine payload must still be inflated.
func TestExtractPDFStrayStreamKeyword(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	b.WriteString("/Name /upstream_thing  % a comment mentioning stream here\n")
	b.WriteString("1 0 obj\n<< /Length 1 >>\nstream\n")
	b.Write(zlibDeflate([]byte("genuine pdf payload after stray keyword")))
	b.WriteString("\nendstream\nendobj\n%%EOF")
	res := Extract(b.Bytes(), time.Time{})
	if !streamsContain(res, "genuine pdf payload") {
		t.Errorf("stray 'stream' hid the real object; got %d streams", len(res.Streams))
	}
}

// Regression (Codex #1): a PDF stuffed with many non-deflate stream bodies must
// be bounded by the attempt cap — the carve loop must stop after maxPDFStreams
// inflate attempts even though none emit a stream, so it cannot scan all
// (maxPDFStreams*4) objects. We assert termination implicitly (no hang, caught
// by `go test`'s timeout) and that no streams were emitted from non-deflate
// bodies. No goroutine: keep the asan thread count low.
func TestExtractPDFAttemptCapBounded(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	for i := 0; i < maxPDFStreams*4; i++ {
		b.WriteString("obj\nstream\nNOTDEFLATE rawbytes here\nendstream\n")
	}
	res := Extract(b.Bytes(), time.Time{})
	if len(res.Streams) != 0 {
		t.Errorf("non-deflate bodies should emit nothing, got %d streams", len(res.Streams))
	}
}

// A non-PDF buffer must not be flagged IsPDF.
func TestExtractNotPDF(t *testing.T) {
	res := Extract([]byte("not a pdf, just text"), time.Time{})
	if res.IsPDF {
		t.Error("plain text wrongly flagged IsPDF")
	}
}

// --- PDF-DEEPEN structural indicators ---

// An /OpenAction that runs /JavaScript must surface PDF-OPENACTION-JS.
func TestExtractPDFOpenActionJS(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "PDF-OPENACTION-JS") {
		t.Errorf("auto-run JS not flagged; streams=%v", res.Streams)
	}
}

// /Launch, /EmbeddedFile, /JBIG2Decode, /AA, /ObjStm each get their own marker.
func TestExtractPDFIndicatorMarkers(t *testing.T) {
	cases := []struct {
		body, marker string
	}{
		{"<< /Launch << /F (cmd.exe) >> >>", "PDF-LAUNCH"},
		{"<< /Type /Filespec /EmbeddedFile 2 0 R >>", "PDF-EMBEDDEDFILE"},
		{"<< /Filter /JBIG2Decode >>", "PDF-JBIG2"},
		{"<< /AA << /O 3 0 R >> >>", "PDF-AA-ACTION"},
		{"<< /Type /ObjStm /N 5 >>", "PDF-OBJSTM"},
	}
	for _, c := range cases {
		buf := []byte("%PDF-1.7\n1 0 obj\n" + c.body + "\nendobj\n%%EOF")
		res := Extract(buf, time.Time{})
		if !streamsContain(res, c.marker) {
			t.Errorf("%s not flagged for body %q; streams=%v", c.marker, c.body, res.Streams)
		}
	}
}

// A hex-escaped name (/J#61vaScript = /JavaScript) must both de-obfuscate to fire
// PDF-OPENACTION-JS and raise PDF-HEXOBFUSC.
func TestExtractPDFHexObfuscatedName(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /J#61vaScript /JS (x) >> >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "PDF-HEXOBFUSC") {
		t.Errorf("hex-escape obfuscation not flagged; streams=%v", res.Streams)
	}
	if !streamsContain(res, "PDF-OPENACTION-JS") {
		t.Errorf("de-obfuscated /JavaScript not matched; streams=%v", res.Streams)
	}
}

// A short name like /JS must not match inside a longer name (/JSomething), and a
// benign PDF must emit no indicator markers (no false positives).
func TestExtractPDFNoFalsePositive(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Page /JSomething (not js) /Contents 2 0 R >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	for _, m := range []string{"PDF-OPENACTION-JS", "PDF-LAUNCH", "PDF-AA-ACTION", "PDF-JBIG2", "PDF-EMBEDDEDFILE", "PDF-OBJSTM", "PDF-HEXOBFUSC"} {
		if streamsContain(res, m) {
			t.Errorf("false positive %s on benign PDF; streams=%v", m, res.Streams)
		}
	}
}

// An escaped delimiter (#2F = '/', #20 = space) inside a name is a LITERAL name
// char and must NOT be decoded into a boundary that fabricates a keyword.
func TestExtractPDFEscapedDelimiterNoFabrication(t *testing.T) {
	// /foo#2FLaunch would become /foo/Launch if #2F were decoded to '/'.
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /foo#2FLaunch (x) /OpenAction#20y 1 0 R >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	if streamsContain(res, "PDF-LAUNCH") {
		t.Errorf("escaped delimiter fabricated /Launch; streams=%v", res.Streams)
	}
	if streamsContain(res, "PDF-OPENACTION-JS") {
		t.Errorf("escaped space fabricated /OpenAction match; streams=%v", res.Streams)
	}
	// The escape is still present, so the obfuscation signal must fire.
	if !streamsContain(res, "PDF-HEXOBFUSC") {
		t.Errorf("hex escape not counted as obfuscation; streams=%v", res.Streams)
	}
}

// AUDIT-PDF-LEXER: an indicator name embedded in a literal string, a comment, a
// hex string, or a stream body must NOT fabricate a marker (FP injection).
func TestExtractPDFIndicatorContextScrub(t *testing.T) {
	cases := []struct{ name, body string }{
		{"literal-string", "1 0 obj\n<< /Title (see /OpenAction and /JS in this caption) >>\nendobj"},
		{"comment", "1 0 obj\n% /OpenAction /JS /Launch /JBIG2Decode are discussed here\n<< /Type /Page >>\nendobj"},
		{"hex-string", "1 0 obj\n<< /Title </OpenAction and /JS inside angle brackets> >>\nendobj"},
		{"stream-body", "1 0 obj\n<< /Length 40 >>\nstream\n/OpenAction /JS /Launch /JBIG2Decode\nendstream\nendobj"},
	}
	for _, c := range cases {
		buf := []byte("%PDF-1.7\n" + c.body + "\n%%EOF")
		res := Extract(buf, time.Time{})
		for _, m := range []string{"PDF-OPENACTION-JS", "PDF-LAUNCH", "PDF-JBIG2"} {
			if streamsContain(res, m) {
				t.Errorf("[%s] fabricated %s from non-name context; streams=%v", c.name, m, res.Streams)
			}
		}
	}
}

// A stream whose body contains the literal bytes "endstream" followed by fake
// indicator names must NOT fabricate markers: /Length tells the scrubber the
// exact body size, so the embedded "endstream" + fake names stay inside the body.
func TestExtractPDFStreamEndstreamInBody(t *testing.T) {
	body := "binary endstream /OpenAction /JS /Launch more binary"
	obj := "1 0 obj\n<< /Length " + strconv.Itoa(len(body)) + " >>\nstream\n" + body + "\nendstream\nendobj"
	buf := []byte("%PDF-1.7\n" + obj + "\n%%EOF")
	res := Extract(buf, time.Time{})
	for _, m := range []string{"PDF-OPENACTION-JS", "PDF-LAUNCH"} {
		if streamsContain(res, m) {
			t.Errorf("fabricated %s from a stream body containing 'endstream'; streams=%v", m, res.Streams)
		}
	}
}

// zlibStore zlib-wraps data with NO compression (stored blocks), so the
// compressed bytes contain the literal payload — letting a test embed an
// `endstream` token inside an otherwise-valid FlateDecode body.
func zlibStore(data []byte) []byte {
	var b bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&b, zlib.NoCompression)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return b.Bytes()
}

// AUDIT-PDF-ENDSTREAM: a FlateDecode body whose compressed bytes contain a
// literal `endstream` must be carved by its declared /Length, not truncated at
// the first `endstream` substring — otherwise the inflate drops everything past
// the embedded token and the real payload tail evades scanning.
func TestExtractPDFEndstreamInCompressedBody(t *testing.T) {
	payload := []byte("app.alert('PDF_HEAD'); /* endstream */ this.exportDataObject('PDF_TAIL_KEYWORD')")
	comp := zlibStore(payload)
	if !bytes.Contains(comp, []byte("endstream")) {
		t.Fatalf("test setup: stored-deflate body does not contain a literal 'endstream'")
	}
	obj := "1 0 obj\n<< /Length " + strconv.Itoa(len(comp)) + " >>\nstream\n"
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	buf.WriteString(obj)
	buf.Write(comp)
	buf.WriteString("\nendstream\nendobj\n%%EOF")

	res := Extract(buf.Bytes(), time.Time{})
	if !streamsContain(res, "PDF_TAIL_KEYWORD") {
		t.Errorf("payload past the embedded 'endstream' not inflated (carve truncated early); streams=%v", res.Streams)
	}
}

func ascii85Encode(data []byte) []byte {
	var b bytes.Buffer
	w := ascii85.NewEncoder(&b)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

// pdfWithFilter wraps body in a single PDF object carrying the given /Filter and
// a correct direct /Length.
func pdfWithFilter(filter string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n1 0 obj\n<< /Length " + strconv.Itoa(len(body)) + " /Filter " + filter + " >>\nstream\n")
	b.Write(body)
	b.WriteString("\nendstream\nendobj\n%%EOF")
	return b.Bytes()
}

// AUDIT-PDF-FILTER-CHAIN: an ASCII85Decode→FlateDecode chain (the deflate body
// armoured as ASCII85 text) must be un-armoured then inflated, surfacing the JS.
func TestExtractPDFASCII85FlateChain(t *testing.T) {
	js := []byte("app.alert('A85_FLATE_CHAIN_JS_KEYWORD'); this.exportDataObject()")
	body := ascii85Encode(zlibDeflate(js))
	res := Extract(pdfWithFilter("[/ASCII85Decode /FlateDecode]", body), time.Time{})
	if !streamsContain(res, "A85_FLATE_CHAIN_JS_KEYWORD") {
		t.Errorf("ASCII85→Flate chain not decoded+inflated; streams=%v", res.Streams)
	}
}

// ASCIIHexDecode→FlateDecode chain (with the '>' EOD marker).
func TestExtractPDFASCIIHexFlateChain(t *testing.T) {
	js := []byte("this.exportDataObject('AHX_FLATE_CHAIN_JS_KEYWORD')")
	body := append([]byte(hex.EncodeToString(zlibDeflate(js))), '>')
	res := Extract(pdfWithFilter("[/ASCIIHexDecode /FlateDecode]", body), time.Time{})
	if !streamsContain(res, "AHX_FLATE_CHAIN_JS_KEYWORD") {
		t.Errorf("ASCIIHex→Flate chain not decoded+inflated; streams=%v", res.Streams)
	}
}

// A prefilter-only chain (bare /ASCII85Decode, no Flate) must surface the decoded
// cleartext directly.
func TestExtractPDFASCII85Only(t *testing.T) {
	payload := []byte("/JS bare_ASCII85_CLEARTEXT_KEYWORD app.alert(1)")
	res := Extract(pdfWithFilter("/ASCII85Decode", ascii85Encode(payload)), time.Time{})
	if !streamsContain(res, "bare_ASCII85_CLEARTEXT_KEYWORD") {
		t.Errorf("bare ASCII85 cleartext not surfaced; streams=%v", res.Streams)
	}
}

// Evasion (golang-pro audit F2): a prefilter-only `/Filter /ASCII85Decode` whose
// decoded bytes are RAW deflate (the dict dropped the trailing /FlateDecode) must
// still surface the JS — the surface path emits the raw-inflated stream in
// addition to the (compressed) cleartext, so YARA isn't blinded by deflate bytes.
func TestExtractPDFASCII85RawDeflateNoFlateName(t *testing.T) {
	js := []byte("app.alert('A85_RAWDEFLATE_NOFILTERNAME_KEYWORD')")
	body := ascii85Encode(rawDeflate(js))
	res := Extract(pdfWithFilter("/ASCII85Decode", body), time.Time{})
	if !streamsContain(res, "A85_RAWDEFLATE_NOFILTERNAME_KEYWORD") {
		t.Errorf("prefilter-only ASCII85 wrapping raw-deflate evaded extraction; streams=%v", res.Streams)
	}
}

// Boundary (golang-pro audit F1): "/FilterFoo" must never be parsed as "/Filter"
// even when it abuts the search-window end — pdfStreamFilters must reject it.
func TestPDFStreamFiltersShadowAtWindowEnd(t *testing.T) {
	// /FilterFoo with the value (a name) right up against `stream`; no real /Filter.
	s := "1 0 obj\n<< /FilterFoo /ASCII85Decode >>stream\n"
	sp := strings.Index(s, "stream")
	if got := pdfStreamFilters([]byte(s), sp); got != nil {
		t.Errorf("/FilterFoo shadowed /Filter at window end, got %v", got)
	}
}

// Filter abbreviations (A85 / Fl) must be recognised the same as the long names.
func TestExtractPDFFilterAbbrev(t *testing.T) {
	js := []byte("app.alert('A85_ABBREV_JS_KEYWORD')")
	body := ascii85Encode(zlibDeflate(js))
	res := Extract(pdfWithFilter("[/A85 /Fl]", body), time.Time{})
	if !streamsContain(res, "A85_ABBREV_JS_KEYWORD") {
		t.Errorf("abbreviated filter chain not handled; streams=%v", res.Streams)
	}
}

// A decoy `/Filter` (e.g. picked by LastIndex from a string value) must NOT be
// able to disable extraction of a real deflate stream: the body-inflate fallback
// recovers it.
func TestExtractPDFDecoyFilterRecovered(t *testing.T) {
	js := []byte("app.alert('DECOY_FILTER_RECOVERED_JS_KEYWORD')")
	body := zlibDeflate(js)
	// Real filter is /FlateDecode; a decoy "/Filter /ASCII85Decode" hides in a
	// /Title string AFTER it, so pdfStreamFilters' LastIndex picks the decoy.
	dict := "<< /Filter /FlateDecode /Title (x /Filter /ASCII85Decode x) /Length " + strconv.Itoa(len(body)) + " >>"
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n1 0 obj\n" + dict + "\nstream\n")
	buf.Write(body)
	buf.WriteString("\nendstream\nendobj\n%%EOF")
	res := Extract(buf.Bytes(), time.Time{})
	if !streamsContain(res, "DECOY_FILTER_RECOVERED_JS_KEYWORD") {
		t.Errorf("decoy /Filter disabled extraction of a real deflate stream; streams=%v", res.Streams)
	}
}

// A decoy `/Filter /FlateDecode` in a string must NOT hide a real armoured
// `[/ASCII85Decode /FlateDecode]` chain: the opportunistic un-armour retry
// recovers the payload even when the dict scan picks the decoy.
func TestExtractPDFDecoyFlateHidesArmouredChain(t *testing.T) {
	js := []byte("app.alert('DECOY_FLATE_ARMOURED_RECOVERED_KEYWORD')")
	body := ascii85Encode(zlibDeflate(js))
	dict := "<< /Filter [/ASCII85Decode /FlateDecode] /Note (x /Filter /FlateDecode x) /Length " + strconv.Itoa(len(body)) + " >>"
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n1 0 obj\n" + dict + "\nstream\n")
	buf.Write(body)
	buf.WriteString("\nendstream\nendobj\n%%EOF")
	res := Extract(buf.Bytes(), time.Time{})
	if !streamsContain(res, "DECOY_FLATE_ARMOURED_RECOVERED_KEYWORD") {
		t.Errorf("decoy /FlateDecode hid the real armoured chain; streams=%v", res.Streams)
	}
}

// A decoy prefilter-only `/Filter /ASCII85Decode` in a string must NOT override
// the real `[/ASCII85Decode /FlateDecode]` chain (which would make the surface
// path emit still-compressed bytes): the window scrub blanks the string decoy so
// the real chain is parsed and the body is inflated.
func TestExtractPDFDecoyPrefilterOnlyInString(t *testing.T) {
	js := []byte("app.alert('DECOY_PREFILTER_ONLY_RECOVERED_KEYWORD')")
	body := ascii85Encode(zlibDeflate(js))
	dict := "<< /Filter [/ASCII85Decode /FlateDecode] /Note (z /Filter /ASCII85Decode z) /Length " + strconv.Itoa(len(body)) + " >>"
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n1 0 obj\n" + dict + "\nstream\n")
	buf.Write(body)
	buf.WriteString("\nendstream\nendobj\n%%EOF")
	res := Extract(buf.Bytes(), time.Time{})
	if !streamsContain(res, "DECOY_PREFILTER_ONLY_RECOVERED_KEYWORD") {
		t.Errorf("decoy prefilter-only /Filter in a string broke real-chain extraction; streams=%v", res.Streams)
	}
}

// An unterminated `(` before the real /Filter must NOT blank through and erase
// it (over-blank evasion): a prefilter-only stream must still surface.
func TestExtractPDFUnterminatedStringKeepsFilter(t *testing.T) {
	payload := []byte("UNTERMINATED_KEPT_FILTER_CLEARTEXT_KEYWORD app.alert(1)")
	body := ascii85Encode(payload)
	dict := "<< /Title (oops-no-close-paren /Filter /ASCII85Decode /Length " + strconv.Itoa(len(body)) + " >>"
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n1 0 obj\n" + dict + "\nstream\n")
	buf.Write(body)
	buf.WriteString("\nendstream\nendobj\n%%EOF")
	res := Extract(buf.Bytes(), time.Time{})
	if !streamsContain(res, "UNTERMINATED_KEPT_FILTER_CLEARTEXT_KEYWORD") {
		t.Errorf("unterminated '(' erased the real /Filter; streams=%v", res.Streams)
	}
}

// A decoy prefilter-only /Filter hidden in an UNTERMINATED string (left visible
// by the scrub) can win LastIndex and force the surface path; the zlib-recheck
// must self-correct by inflating the genuinely-compressed body.
func TestExtractPDFUnterminatedDecoySurfaceSelfCorrects(t *testing.T) {
	js := []byte("app.alert('UNTERM_DECOY_SELFCORRECT_KEYWORD')")
	body := ascii85Encode(zlibDeflate(js))
	dict := "<< /Filter [/ASCII85Decode /FlateDecode] /Length " + strconv.Itoa(len(body)) + " /X (oops /Filter /ASCII85Decode >>"
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n1 0 obj\n" + dict + "\nstream\n")
	buf.Write(body)
	buf.WriteString("\nendstream\nendobj\n%%EOF")
	res := Extract(buf.Bytes(), time.Time{})
	if !streamsContain(res, "UNTERM_DECOY_SELFCORRECT_KEYWORD") {
		t.Errorf("surface zlib-recheck failed to self-correct a mis-parsed /Filter; streams=%v", res.Streams)
	}
}

// A chain with a terminal binary filter (/ASCII85Decode → /DCTDecode) must NOT
// surface the un-armoured (still-binary, non-cleartext) bytes as a stream.
func TestExtractPDFASCII85DCTNotSurfaced(t *testing.T) {
	decoy := []byte("NOT_CLEARTEXT_SHOULD_NOT_SURFACE_KEYWORD")
	res := Extract(pdfWithFilter("[/ASCII85Decode /DCTDecode]", ascii85Encode(decoy)), time.Time{})
	if streamsContain(res, "NOT_CLEARTEXT_SHOULD_NOT_SURFACE_KEYWORD") {
		t.Errorf("ASCII85→DCT (binary terminal) wrongly surfaced as cleartext; streams=%v", res.Streams)
	}
}

// pdfStreamFilters parsing: single name, array, abbreviation, indirect → nil.
func TestPDFStreamFilters(t *testing.T) {
	sp := func(s string) int { return strings.Index(s, "stream") }
	eq := func(got []string, want ...string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}
	single := "1 0 obj\n<< /Filter /FlateDecode >>\nstream\n"
	if !eq(pdfStreamFilters([]byte(single), sp(single)), "FlateDecode") {
		t.Errorf("single: %v", pdfStreamFilters([]byte(single), sp(single)))
	}
	arr := "1 0 obj\n<< /Filter [ /ASCII85Decode /FlateDecode ] >>\nstream\n"
	if !eq(pdfStreamFilters([]byte(arr), sp(arr)), "ASCII85Decode", "FlateDecode") {
		t.Errorf("array: %v", pdfStreamFilters([]byte(arr), sp(arr)))
	}
	// Hex-escaped name /ASCII#38#35Decode must decode to ASCII85Decode (#XX, 7.3.5).
	hexName := "1 0 obj\n<< /Filter /ASCII#38#35Decode >>\nstream\n"
	if !eq(pdfStreamFilters([]byte(hexName), sp(hexName)), "ASCII85Decode") {
		t.Errorf("hex-escaped filter name: %v", pdfStreamFilters([]byte(hexName), sp(hexName)))
	}
	// Indirect /Filter — unresolvable, must be nil.
	ind := "1 0 obj\n<< /Filter 7 0 R >>\nstream\n"
	if got := pdfStreamFilters([]byte(ind), sp(ind)); got != nil {
		t.Errorf("indirect /Filter should be nil, got %v", got)
	}
	// Array with a trailing indirect ref — partial/unresolvable, must be nil (not
	// a truncated ["ASCII85Decode"] that would be treated as prefilter-only).
	arrInd := "1 0 obj\n<< /Filter [ /ASCII85Decode 7 0 R ] >>\nstream\n"
	if got := pdfStreamFilters([]byte(arrInd), sp(arrInd)); got != nil {
		t.Errorf("array with indirect element should be nil, got %v", got)
	}
	// /FilterFoo must not shadow /Filter.
	shadow := "1 0 obj\n<< /FilterFoo /X >>\nstream\n"
	if got := pdfStreamFilters([]byte(shadow), sp(shadow)); got != nil {
		t.Errorf("/FilterFoo shadowed /Filter, got %v", got)
	}
}

// pdfStreamLength / readPDFLength: direct integer trusted, indirect refs and a
// prior object's /Length rejected (the latter must not leak across objects).
func TestPDFStreamLength(t *testing.T) {
	streamPos := func(b string) int { return bytes.Index([]byte(b), []byte("stream")) }

	direct := "1 0 obj\n<< /Type /X /Length 42 >>\nstream\n"
	if got := pdfStreamLength([]byte(direct), streamPos(direct)); got != 42 {
		t.Errorf("direct /Length: got %d, want 42", got)
	}
	// Indirect `/Length 9 0 R` — unresolvable, must be -1.
	indirect := "2 0 obj\n<< /Length 9 0 R >>\nstream\n"
	if got := pdfStreamLength([]byte(indirect), streamPos(indirect)); got != -1 {
		t.Errorf("indirect /Length: got %d, want -1", got)
	}
	// Indirect split by a comment `/Length 9 %c\n0 R` — still -1 (comment is ws).
	commented := "3 0 obj\n<< /Length 9 %c\n0 R >>\nstream\n"
	if got := pdfStreamLength([]byte(commented), streamPos(commented)); got != -1 {
		t.Errorf("comment-split indirect /Length: got %d, want -1", got)
	}
	// /Length only in a PRIOR object; this stream's object has none → -1.
	stale := "1 0 obj\n<< /Length 5 >>\nendobj\n2 0 obj\n<< /Type /X >>\nstream\n"
	if got := pdfStreamLength([]byte(stale), strings.LastIndex(stale, "stream")); got != -1 {
		t.Errorf("prior-object /Length leaked: got %d, want -1", got)
	}
}

// A real dictionary /OpenAction must still fire even when the document ALSO
// contains a decoy /OpenAction inside a string (scrub keeps real names).
func TestExtractPDFIndicatorRealAfterDecoy(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /Title (decoy /OpenAction here) >>\nendobj\n" +
		"2 0 obj\n<< /OpenAction << /S /JavaScript /JS (real) >> >>\nendobj\n%%EOF")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "PDF-OPENACTION-JS") {
		t.Errorf("real /OpenAction not detected past a string decoy; streams=%v", res.Streams)
	}
}

// pdfHasName must respect name-token boundaries.
func TestPDFHasNameBoundary(t *testing.T) {
	if pdfHasName([]byte("<< /JSomething >>"), pdfNameJS) {
		t.Error("/JS matched inside /JSomething")
	}
	if !pdfHasName([]byte("<< /JS 1 0 R >>"), pdfNameJS) {
		t.Error("/JS not matched as a whole name")
	}
	if !pdfHasName([]byte("/ObjStm"), pdfNameObjStm) {
		t.Error("/ObjStm at end-of-buffer not matched")
	}
}
