package extract

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// streamHas reports whether res.Streams (or res.Markers) contains an entry equal
// to want. fromHTMLSmuggling emits markers into Streams; the splitPureMarkers
// pass that moves them to Markers runs only in the full Extract path, so the
// unit tests here inspect Streams directly.
func streamHas(res *Result, want string) bool {
	for _, s := range res.Streams {
		if string(s) == want {
			return true
		}
	}
	return false
}

func runHTML(buf []byte) *Result {
	res := &Result{childOpts: FullOptions(time.Time{})}
	fromHTMLSmuggling(buf, res, &archiveBudget{}, 0, time.Time{})
	return res
}

func TestHTMLSmugglingBlobMarker(t *testing.T) {
	pos := []string{
		// classic: atob → Blob → object URL → anchor download.click()
		`<script>var b=new Blob([atob(data)]);var u=URL.createObjectURL(b);
		 var a=document.createElement('a');a.href=u;a.download='invoice.exe';a.click();</script>`,
		// createObjectURL + download attribute in markup
		`<a id=x download="report.iso"></a><script>x.href=URL.createObjectURL(blob);</script>`,
		// msSaveBlob (IE/Edge legacy) + download intent
		`<script>navigator.msSaveBlob(blob,'x.zip');a.download='x.zip';</script>`,
	}
	for _, in := range pos {
		res := runHTML([]byte(in))
		if !streamHas(res, "HTML-SMUGGLING-BLOB") {
			t.Errorf("expected HTML-SMUGGLING-BLOB for:\n%s", in)
		}
	}
}

func TestHTMLSmugglingBlobNoFalsePositive(t *testing.T) {
	// Each lacks one half of the combo, or is benign markup.
	neg := []string{
		`<img src="cat.jpg"><p>hello world</p>`,                       // plain HTML
		`<script>var u=URL.createObjectURL(blob);img.src=u;</script>`, // blob, no download
		`<a href="/files/report.pdf" download="report.pdf">save</a>`,  // download, no blob reconstruct
		`<script>var x=atob("aGk=");console.log(x);</script>`,         // atob, no blob, no download
		`download = configValue;`,                                     // "download" word, no blob API
		``,                                                            // empty
	}
	for _, in := range neg {
		res := runHTML([]byte(in))
		if streamHas(res, "HTML-SMUGGLING-BLOB") {
			t.Errorf("unexpected HTML-SMUGGLING-BLOB (false positive) for:\n%s", in)
		}
	}
}

func TestHTMLSmugglingDataURICarve(t *testing.T) {
	// A force-downloaded base64 data: URI whose payload is a ZIP (PK magic).
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x41}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	in := `<a download="x.zip" href="data:application/octet-stream;base64,` + b64 + `">get</a>`
	res := runHTML([]byte(in))
	if !streamHas(res, "HTML-SMUGGLING-DATAURI") {
		t.Fatal("expected HTML-SMUGGLING-DATAURI marker")
	}
	// The decoded PK payload must be added as a stream (carved for the rule set).
	found := false
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
			found = true
		}
	}
	if !found {
		t.Error("decoded data: URI payload was not carved into Streams")
	}
}

func TestHTMLDataURINoDownloadNoCarve(t *testing.T) {
	// An inline data:image with NO download attribute must not fire/carve.
	b64 := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nfakepngbytes"))
	in := `<img src="data:image/png;base64,` + b64 + `">`
	res := runHTML([]byte(in))
	if streamHas(res, "HTML-SMUGGLING-DATAURI") {
		t.Error("inline data:image without download attr must not emit HTML-SMUGGLING-DATAURI")
	}
}

func TestSVGScriptMarker(t *testing.T) {
	pos := []string{
		`<svg xmlns="http://www.w3.org/2000/svg"><script>location='http://evil'</script></svg>`,
		`<svg onload="alert(1)"></svg>`,
		`<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>x()</script></body></foreignObject></svg>`,
	}
	for _, in := range pos {
		if !streamHas(runHTML([]byte(in)), "SVG-SCRIPT") {
			t.Errorf("expected SVG-SCRIPT for:\n%s", in)
		}
	}
	// Plain (non-scripted) SVG must not fire.
	if streamHas(runHTML([]byte(`<svg><rect width="10" height="10"/></svg>`)), "SVG-SCRIPT") {
		t.Error("plain SVG must not emit SVG-SCRIPT")
	}
}

// TestSVGEmbeddedPayloadCarve: an <svg> with an <image href> base64 data: URI
// whose decoded bytes are a container magic (PK zip) must emit
// SVG-EMBEDDED-PAYLOAD and carve the dropper — no download attribute required.
func TestSVGEmbeddedPayloadCarve(t *testing.T) {
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x43}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	in := `<svg xmlns="http://www.w3.org/2000/svg">` +
		`<image href="data:application/octet-stream;base64,` + b64 + `"/></svg>`
	res := runHTML([]byte(in))
	if !streamHas(res, "SVG-EMBEDDED-PAYLOAD") {
		t.Fatalf("expected SVG-EMBEDDED-PAYLOAD marker; streams=%d", len(res.Streams))
	}
	found := false
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
			found = true
		}
	}
	if !found {
		t.Error("decoded SVG-embedded payload was not carved into Streams")
	}
}

// TestSVGEmbeddedPayloadXlinkHref: the legacy xlink:href spelling carries the
// same data: URI and must be carved identically.
func TestSVGEmbeddedPayloadXlinkHref(t *testing.T) {
	payload := append([]byte("%PDF-1.7"), bytes.Repeat([]byte{0x44}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	in := `<svg><image xlink:href="data:image/png;base64,` + b64 + `"/></svg>`
	if !streamHas(runHTML([]byte(in)), "SVG-EMBEDDED-PAYLOAD") {
		t.Error("expected SVG-EMBEDDED-PAYLOAD for xlink:href container payload")
	}
}

// TestSVGEmbeddedPayloadNoFalsePositive: an <svg> inlining real raster art (PNG,
// not a container magic) must NOT fire — legitimate SVG inlines images.
func TestSVGEmbeddedPayloadNoFalsePositive(t *testing.T) {
	// A real-ish PNG header — NOT a container magic (PK/OLE2/MZ/%PDF).
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x10}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(png)
	in := `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,` + b64 + `"/></svg>`
	res := runHTML([]byte(in))
	if streamHas(res, "SVG-EMBEDDED-PAYLOAD") {
		t.Error("benign inline PNG in SVG wrongly emitted SVG-EMBEDDED-PAYLOAD")
	}
}

// TestSVGEmbeddedPayloadNotFromPlainHTML: a container data: URI in plain HTML
// (no <svg> root) must not be attributed to the SVG path.
func TestSVGEmbeddedPayloadNotFromPlainHTML(t *testing.T) {
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x45}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	// No <svg>: must NOT be attributed to the SVG path. A container payload in a
	// non-downloaded data: URI in plain HTML now carves on the general path as
	// HTML-DATAURI-CONTAINER instead (the container magic is the FP firewall).
	in := `<img src="data:application/octet-stream;base64,` + b64 + `">`
	res := runHTML([]byte(in))
	if streamHas(res, "SVG-EMBEDDED-PAYLOAD") {
		t.Error("non-SVG container data: URI wrongly emitted SVG-EMBEDDED-PAYLOAD")
	}
	if !streamHas(res, "HTML-DATAURI-CONTAINER") {
		t.Error("plain-HTML container data: URI must emit HTML-DATAURI-CONTAINER")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
			found = true
		}
	}
	if !found {
		t.Error("decoded PK container should be carved as a child stream")
	}
}

func TestHTMLDataURIContainerNoFalsePositive(t *testing.T) {
	// Non-container payload (a real PNG) with no download attr must NOT carve.
	payload := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x46}, 64)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	in := `<img src="data:image/png;base64,` + b64 + `">`
	res := runHTML([]byte(in))
	if streamHas(res, "HTML-DATAURI-CONTAINER") {
		t.Error("benign inline data:image must not emit HTML-DATAURI-CONTAINER")
	}
}

func TestHTMLSmugglingGateAndFailOpen(t *testing.T) {
	// Non-markup / binary garbage must short-circuit and emit nothing (no panic).
	res := runHTML([]byte{0x00, 0x01, 0x02, 0xff, 0xfe})
	if len(res.Streams) != 0 {
		t.Errorf("non-markup input produced %d streams, want 0", len(res.Streams))
	}
	res = runHTML([]byte(strings.Repeat("just some prose with no tags ", 100)))
	if len(res.Streams) != 0 {
		t.Errorf("plain prose produced %d streams, want 0", len(res.Streams))
	}
}

func TestHTMLDataURICarveCapped(t *testing.T) {
	// Many force-downloaded data: URIs: carve count must be bounded by htmlMaxDataURIs.
	payload := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0x42}, 32)...)
	b64 := base64.StdEncoding.EncodeToString(payload)
	var sb strings.Builder
	sb.WriteString(`<a download="x">`)
	for i := 0; i < htmlMaxDataURIs+10; i++ {
		sb.WriteString(`<a href="data:x;base64,` + b64 + `">`)
	}
	res := runHTML([]byte(sb.String()))
	carved := 0
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, []byte("PK\x03\x04")) {
			carved++
		}
	}
	if carved > htmlMaxDataURIs {
		t.Errorf("carved %d data: URIs, want <= %d (cap)", carved, htmlMaxDataURIs)
	}
}

// HTML-smuggling triage must reach an .html part nested inside an archive, not
// just a top-level text part (PR #190 covered top-level only; the extractChild
// default path now also runs fromHTMLSmuggling). A blob-reconstruct+download
// HTML stored in a zip must still surface HTML-SMUGGLING-BLOB.
func TestHTMLSmugglingNestedInZip(t *testing.T) {
	html := []byte(`<script>var b=new Blob([atob(data)]);var u=URL.createObjectURL(b);` +
		`var a=document.createElement('a');a.href=u;a.download='invoice.exe';a.click();</script>`)
	zipBuf := buildZip(t, map[string][]byte{"invoice.html": html})
	res := Extract(zipBuf, time.Time{})
	if !streamsContain(res, "HTML-SMUGGLING-BLOB") {
		t.Error("HTML smuggling inside a zip member was not detected (nested path)")
	}
}
