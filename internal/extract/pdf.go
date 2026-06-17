package extract

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"
)

// PDF pre-extraction. Malicious PDFs hide their payload inside FlateDecode
// (zlib-deflated) object streams: the `/OpenAction`/`/Launch`/`/JS`/
// `/JavaScript` action and the JavaScript body, or an embedded file, are
// compressed, so raw-byte keyword rules scanning the .pdf never see the
// decompressed script. yarad's other extractors don't recognise a PDF (it is
// neither OLE2, ZIP, nor a shell link).
//
// fromPDF carves every `stream … endstream` object body, inflates it
// (zlib, then raw-deflate as a fallback), and surfaces the decompressed bytes so
// the rules match the hidden JS / actions / embedded data. We deliberately do
// NOT build a full PDF object/xref parser — carving by the stream delimiters is
// robust against the malformed/linearised/hybrid xref tricks maldocs use, the
// same pragmatic approach AV unpackers take. Best-effort and fail-open: a stream
// that isn't deflate, or is truncated, is skipped, never fatal (Extract's recover
// also covers a panic).

// pdfMagic — "%PDF-" appears at (or very near) the start of every PDF.
var (
	pdfMagic     = []byte("%PDF-")
	pdfStreamKW  = []byte("stream")
	pdfEndStream = []byte("endstream")
)

const (
	// maxPDFStreams bounds how many object streams we inflate from one PDF.
	maxPDFStreams = 256
	// maxBytesPerPDFStream caps one inflated stream (decompression-bomb guard);
	// the raw scan still covers anything larger.
	maxBytesPerPDFStream = 8 << 20
	// maxTotalPDF caps cumulative inflated bytes emitted from one PDF.
	maxTotalPDF = 64 << 20
	// maxPDFScan bounds how far into the file we look for stream delimiters, so a
	// huge PDF can't cause an unbounded number of carve attempts.
	maxPDFScan = 64 << 20
)

// isPDF reports whether buf is a PDF. The magic is usually at offset 0 but the
// spec tolerates leading bytes, so accept it within the first 1 KiB.
func isPDF(buf []byte) bool {
	if bytes.HasPrefix(buf, pdfMagic) {
		return true
	}
	head := buf
	if len(head) > 1024 {
		head = head[:1024]
	}
	return bytes.Contains(head, pdfMagic)
}

// fromPDF carves and inflates the object streams of a PDF, appending each
// decompressed body to res.Streams. Sets IsPDF. Bounded by the maxPDF* caps.
func fromPDF(buf []byte, res *Result) {
	res.IsPDF = true
	scan := buf
	if len(scan) > maxPDFScan {
		scan = scan[:maxPDFScan]
	}
	var total, attempts int
	pos := 0
	// Cap inflate ATTEMPTS, not just emitted streams: a hostile PDF stuffed with
	// many non-deflate `stream … endstream` bodies would otherwise force unbounded
	// zlib/flate attempts (none of which increment len(res.Streams)).
	for attempts < maxPDFStreams && len(res.Streams) < maxStreams && total < maxTotalPDF {
		rel := bytes.Index(scan[pos:], pdfStreamKW)
		if rel < 0 {
			break
		}
		kwAt := pos + rel
		bodyStart := kwAt + len(pdfStreamKW)
		// Require a real `stream` token, not a substring of `endstream` or of a
		// name/comment: the keyword must be preceded by a PDF whitespace/delimiter
		// (typically `>>` then EOL) and followed by EOL. Otherwise skip just past
		// this match and keep looking — so a stray "stream" can't make us carve
		// through the next endstream and hide the real object.
		if !pdfTokenBoundary(scan, kwAt, bodyStart) {
			pos = bodyStart
			continue
		}
		// Per the spec the keyword is followed by CRLF or LF before the data. Skip a
		// single EOL so the inflater sees the real first byte.
		bodyStart = skipPDFEOL(scan, bodyStart)
		endRel := bytes.Index(scan[bodyStart:], pdfEndStream)
		if endRel < 0 {
			break // no terminator: truncated/hostile, stop
		}
		body := scan[bodyStart : bodyStart+endRel]
		pos = bodyStart + endRel + len(pdfEndStream)

		attempts++
		dec := inflatePDFStream(body)
		if len(dec) == 0 {
			continue // not a deflate stream (e.g. raw image) — raw scan covers it
		}
		res.Streams = append(res.Streams, dec)
		total += len(dec)
	}
}

// pdfTokenBoundary reports whether the `stream` match at kwAt (body byte at
// after) is a genuine stream-object keyword: the byte before must be a PDF
// whitespace/delimiter (so `endstream` and `upstream` don't match) and the byte
// after must begin an EOL (\r or \n), as the spec mandates.
func pdfTokenBoundary(b []byte, kwAt, after int) bool {
	if kwAt > 0 {
		switch b[kwAt-1] {
		case ' ', '\t', '\r', '\n', '\f', 0, '>':
		default:
			return false
		}
	}
	return after < len(b) && (b[after] == '\r' || b[after] == '\n')
}

// skipPDFEOL advances past one EOL sequence (\r\n, \n, or \r) at off, returning
// the new offset. PDF writes exactly one EOL after the `stream` keyword.
func skipPDFEOL(b []byte, off int) int {
	if off < len(b) && b[off] == '\r' {
		off++
	}
	if off < len(b) && b[off] == '\n' {
		off++
	}
	return off
}

// inflatePDFStream tries to decompress one object body as FlateDecode: zlib
// (the PDF default — a 0x78 header) first, then raw deflate as a fallback for
// producers that omit the zlib wrapper. Output is bounded by maxBytesPerPDFStream
// via io.LimitReader. Returns nil if the body isn't deflate or yields nothing.
func inflatePDFStream(body []byte) []byte {
	if len(body) < 2 {
		return nil
	}
	if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
		if out := readInflated(zr); len(out) > 0 {
			return out
		}
	}
	fr := flate.NewReader(bytes.NewReader(body))
	return readInflated(fr)
}

// readInflated reads a decompressor bounded by maxBytesPerPDFStream. A
// decompression error after some output still returns what was produced (a
// truncated-but-useful stream is better than nothing); zero output returns nil.
func readInflated(r io.Reader) []byte {
	var b bytes.Buffer
	_, _ = b.ReadFrom(io.LimitReader(r, maxBytesPerPDFStream))
	if rc, ok := r.(io.Closer); ok {
		_ = rc.Close()
	}
	if b.Len() == 0 {
		return nil
	}
	return b.Bytes()
}
