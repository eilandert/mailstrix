package extract

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
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
// be bounded by the attempt cap (no unbounded inflate attempts) and terminate.
func TestExtractPDFAttemptCapBounded(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	for i := 0; i < maxPDFStreams*4; i++ {
		b.WriteString("obj\nstream\nNOTDEFLATE rawbytes here\nendstream\n")
	}
	done := make(chan struct{})
	go func() {
		_ = Extract(b.Bytes(), time.Time{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PDF inflate-attempt loop did not terminate (attempt cap missing)")
	}
}

// A non-PDF buffer must not be flagged IsPDF.
func TestExtractNotPDF(t *testing.T) {
	res := Extract([]byte("not a pdf, just text"), time.Time{})
	if res.IsPDF {
		t.Error("plain text wrongly flagged IsPDF")
	}
}
