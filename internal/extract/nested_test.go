package extract

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

// encodedVBEBlock is a canonical MS Script Encoder (#@~^…^#~@) block whose
// decoded cleartext is `MsgBox "Hello"…` — reused from script_test.go's vectors
// to prove a child .vbe carried inside another container is decoded, not left
// opaque.
var encodedVBEBlock = []byte(
	"#@~^DgAAAA==" +
		"\x5c\x6b\x6f\x24\x4b\x36\x2c\x4a\x43\x7f\x56\x5e\x47\x4a\x71\x41\x51\x41\x41\x41\x3d\x3d" +
		"^#~@",
)

// The nested-carrier walker (extractChild) must crack a child carrier one layer
// deep instead of leaving it as opaque bytes. Each test hides a payload behind a
// compression/encoding layer so the keyword is invisible in the raw child bytes;
// surfacing it proves the child's OWN format was extracted, not just scanned raw.

// A .msg attachment that is itself an MS-Script-Encoder (.vbe) block must be
// decoded to cleartext — the attachment previously reached only the raw scan, so
// its encoded body stayed opaque. (A .vbe block tolerates the trailing
// sector-pad zeros buildCFB adds inside the CFB stream; compressed carriers like
// gzip/zip require the exact stream length a real .msg stores, so they are
// covered by the top-level and archive-member tests instead.)
func TestNestedMSGAttachmentEncodedScriptChild(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "__properties_version1.0", mse: 2, data: []byte("props blob")},
		{name: "__attach_version1.0_#00000000", mse: 1},
		{name: "__substg1.0_3701000D", mse: 2, data: encodedVBEBlock},
	})
	res := Extract(buf, time.Time{})
	if !res.IsMSG {
		t.Fatal(".msg not flagged IsMSG")
	}
	if !res.EncodedScript {
		t.Error(".vbe attachment child not flagged EncodedScript (not recursed)")
	}
	if !streamsContain(res, "MsgBox") {
		t.Errorf(".vbe attachment not decoded; got %d streams", len(res.Streams))
	}
}

// A .msg attachment that is a PDF must have its FlateDecode JavaScript inflated.
func TestNestedMSGAttachmentPDFChild(t *testing.T) {
	pdf := pdfWithStream(zlibDeflate([]byte("/JavaScript (app.alert('NESTED_MSG_PDF_JS_KEYWORD'))")))
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "__properties_version1.0", mse: 2, data: []byte("props blob")},
		{name: "__attach_version1.0_#00000000", mse: 1},
		{name: "__substg1.0_3701000D", mse: 2, data: pdf},
	})
	res := Extract(buf, time.Time{})
	if !res.IsMSG {
		t.Fatal(".msg not flagged IsMSG")
	}
	if !res.IsPDF {
		t.Error("PDF attachment child not flagged IsPDF (not recursed)")
	}
	if !streamsContain(res, "NESTED_MSG_PDF_JS_KEYWORD") {
		t.Errorf("PDF attachment JS not inflated; got %d streams", len(res.Streams))
	}
}

// An OLE Package (Ole10Native) payload that is a PDF must have its FlateDecode
// JavaScript inflated — the carved dropper file is itself a carrier.
func TestNestedOLEPackagePDFChild(t *testing.T) {
	pdf := pdfWithStream(zlibDeflate([]byte("OpenAction Launch NESTED_PKG_PDF_JS_KEYWORD")))
	stream := buildOle10Native("d.pdf", "C:\\evil\\d.pdf", "C:\\Temp\\d.pdf", pdf, 0)
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "\x01Ole10Native", mse: 2, data: stream},
	})
	res := Extract(buf, time.Time{})
	if !res.IsOLEPackage {
		t.Fatal("embedded package not flagged IsOLEPackage")
	}
	if !res.IsPDF {
		t.Error("PDF package payload not flagged IsPDF (not recursed)")
	}
	if !streamsContain(res, "NESTED_PKG_PDF_JS_KEYWORD") {
		t.Errorf("package PDF JS not inflated; got %d streams", len(res.Streams))
	}
}

// A zip member that is a PDF must have its JavaScript inflated. Previously the
// archive member walk recursed only into zip/OLE/OneNote children, so a child
// PDF (or RTF/.lnk/script) reached only the raw scan.
func TestNestedArchivePDFChild(t *testing.T) {
	pdf := pdfWithStream(zlibDeflate([]byte("/JavaScript (NESTED_ZIP_PDF_JS_KEYWORD)")))
	zipBytes := buildZip(t, map[string][]byte{"dropper.pdf": pdf})
	res := Extract(zipBytes, time.Time{})
	if !res.IsPDF {
		t.Error("PDF zip member not flagged IsPDF (not recursed)")
	}
	if !streamsContain(res, "NESTED_ZIP_PDF_JS_KEYWORD") {
		t.Errorf("zip-member PDF JS not inflated; got %d streams", len(res.Streams))
	}
}

// A zip member that is an MS-Script-Encoder (.vbe) block must be decoded to
// cleartext — the encoded-script path previously ran only on a top-level input.
func TestNestedArchiveEncodedScriptChild(t *testing.T) {
	zipBytes := buildZip(t, map[string][]byte{"dropper.vbe": encodedVBEBlock})
	res := Extract(zipBytes, time.Time{})
	if !res.EncodedScript {
		t.Error("zip-member .vbe not flagged EncodedScript (not recursed)")
	}
	if !streamsContain(res, "MsgBox") {
		t.Errorf("zip-member .vbe not decoded; got %d streams", len(res.Streams))
	}
}

// Three-level cross-carrier recursion: a zip member that is a .msg whose
// attachment is a PDF. Exercises zip→OLE(.msg)→PDF through extractChild and
// fromOLE's error-branch fromMSG; the innermost PDF JavaScript must be inflated.
func TestNestedArchiveMSGPDFChild(t *testing.T) {
	pdf := pdfWithStream(zlibDeflate([]byte("/JavaScript (DEEP_ZIP_MSG_PDF_KEYWORD)")))
	msg := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "__properties_version1.0", mse: 2, data: []byte("props blob")},
		{name: "__attach_version1.0_#00000000", mse: 1},
		{name: "__substg1.0_3701000D", mse: 2, data: pdf},
	})
	zipBytes := buildZip(t, map[string][]byte{"mail.msg": msg})
	res := Extract(zipBytes, time.Time{})
	if !res.IsMSG {
		t.Error(".msg inside the zip not flagged IsMSG (not recursed)")
	}
	if !streamsContain(res, "DEEP_ZIP_MSG_PDF_KEYWORD") {
		t.Errorf("zip→.msg→PDF JS not inflated; got %d streams", len(res.Streams))
	}
}

// Regression for the overwrite bug Codex caught: fromOOXML/fromOLE must APPEND
// to res.Streams, not assign a fresh slice. A plain archive member emitted before
// an Office-doc member must survive the Office child's (macro-free) extraction —
// without the fix, fromOOXML's `res.Streams = out` wiped every prior stream.
func TestNestedOfficeChildDoesNotWipeSiblings(t *testing.T) {
	docx := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types/>`),
		"word/document.xml":   []byte("ordinary body"),
		"_rels/.rels":         []byte("<Relationships/>"),
	})
	// Outer zip with DETERMINISTIC member order (zip.Reader walks central-directory
	// = write order): the plain member first, the Office doc second, so the Office
	// child is processed AFTER the plain member's stream is already emitted.
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w0, err := zw.Create("a_plain.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w0.Write([]byte("SIBLING_MEMBER_KEYWORD must survive the office child")); err != nil {
		t.Fatal(err)
	}
	w1, err := zw.Create("z_doc.docm")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w1.Write(docx); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	res := Extract(b.Bytes(), time.Time{})
	if !streamsContain(res, "SIBLING_MEMBER_KEYWORD") {
		t.Error("sibling member stream was wiped by the Office child (overwrite regression)")
	}
}

// Deeply nested carriers must terminate at the depth cap, never recurse without
// end. Nine gzip layers wrap a payload; the cap (maxNestDepth) is well below 9,
// so the innermost payload is NOT reached — and the call must return (the test
// completing is itself the no-infinite-recursion proof).
func TestNestedDepthBounded(t *testing.T) {
	data := []byte("DEEP_GZIP_PAYLOAD_KEYWORD")
	for i := 0; i < 9; i++ {
		data = buildGzip(t, data)
	}
	res := Extract(data, time.Time{})
	if streamsContain(res, "DEEP_GZIP_PAYLOAD_KEYWORD") {
		t.Error("payload beyond maxNestDepth was decoded; depth bound not enforced")
	}
}
