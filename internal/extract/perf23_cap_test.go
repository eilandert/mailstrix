// perf23_cap_test.go — PERF-23: verify that each cap fires at exactly the
// right iteration (O(1) local-counter path, not O(n²) rescan).
//
// Uses white-box package extract so we can reference the internal cap
// constants (maxXLSBSupBookDDE, maxCSVDDEMarkers, maxExternalRels,
// maxDDEFields) without exporting them.
package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// buildXLSBStream returns a raw BIFF12 record stream containing n
// BrtBeginSupBook DDE records (sbt=1, server "SRV%d", topic "TOPIC%d").
func buildXLSBStream(n int) []byte {
	var buf []byte
	for i := 0; i < n; i++ {
		var body []byte
		body = binary.LittleEndian.AppendUint16(body, 1) // sbt=1 → DDE
		body = append(body, xlNullableWideString(fmt.Sprintf("SRV%d", i))...)
		body = append(body, xlNullableWideString(fmt.Sprintf("TOPIC%d", i))...)
		buf = append(buf, biff12Record(biff12BrtBeginSupBook, body)...)
	}
	return buf
}

// buildXLSBZip wraps a raw BIFF12 stream in an OOXML zip with the correct
// externalLink path so fromXLSBExternalDDE recognises it.
func buildXLSBZip(tb testing.TB, raw []byte) []byte {
	tb.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.Create("xl/externalLinks/externalLink1.bin")
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		tb.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		tb.Fatal(err)
	}
	return b.Bytes()
}

// countPrefix counts entries in streams whose prefix matches p.
func countPrefix(streams [][]byte, p string) int {
	n := 0
	for _, s := range streams {
		if bytes.HasPrefix(s, []byte(p)) {
			n++
		}
	}
	return n
}

// ─── Fix 1: XLSB-DDE cap ─────────────────────────────────────────────────────

// TestXLSBDDECapFires verifies that scanXLSBSupBookDDE stops emitting exactly
// at maxXLSBSupBookDDE even when the stream carries cap+5 records.
func TestXLSBDDECapFires(t *testing.T) {
	over := maxXLSBSupBookDDE + 5
	raw := buildXLSBStream(over)
	data := buildXLSBZip(t, raw)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromXLSBExternalDDE(zr, &out, time.Time{})
	got := countPrefix(out, "XLSB-DDE ")
	if got != maxXLSBSupBookDDE {
		t.Errorf("XLSB-DDE count = %d, want %d", got, maxXLSBSupBookDDE)
	}
}

// TestXLSBDDEBelowCapPassesThrough verifies that cap-1 records are all emitted.
func TestXLSBDDEBelowCapPassesThrough(t *testing.T) {
	n := maxXLSBSupBookDDE - 1
	raw := buildXLSBStream(n)
	data := buildXLSBZip(t, raw)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromXLSBExternalDDE(zr, &out, time.Time{})
	got := countPrefix(out, "XLSB-DDE ")
	if got != n {
		t.Errorf("XLSB-DDE count = %d, want %d", got, n)
	}
}

// ─── Fix 2: CSV-DDE cap ──────────────────────────────────────────────────────

// buildCSVDDEBuf builds a CSV buffer with n DDE cells, one per line.
func buildCSVDDEBuf(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "=cmd|'/c echo %d'!A1\n", i)
	}
	return []byte(b.String())
}

// TestCSVDDECapFires verifies fromCSVDDE stops at maxCSVDDEMarkers.
func TestCSVDDECapFires(t *testing.T) {
	buf := buildCSVDDEBuf(maxCSVDDEMarkers + 5)
	res := &Result{}
	fromCSVDDE(buf, res, time.Time{})
	got := countPrefix(res.Streams, "CSV-DDE ")
	if got != maxCSVDDEMarkers {
		t.Errorf("CSV-DDE count = %d, want %d", got, maxCSVDDEMarkers)
	}
}

// TestCSVDDEBelowCapPassesThrough verifies cap-1 cells are all emitted.
func TestCSVDDEBelowCapPassesThrough(t *testing.T) {
	n := maxCSVDDEMarkers - 1
	buf := buildCSVDDEBuf(n)
	res := &Result{}
	fromCSVDDE(buf, res, time.Time{})
	got := countPrefix(res.Streams, "CSV-DDE ")
	if got != n {
		t.Errorf("CSV-DDE count = %d, want %d", got, n)
	}
}

// TestScanCSVLineCapFires verifies the inner scanCSVLine cap with many cells
// on a single line (comma-separated).
func TestScanCSVLineCapFires(t *testing.T) {
	var cells []string
	for i := 0; i < maxCSVDDEMarkers+5; i++ {
		cells = append(cells, fmt.Sprintf("=cmd|'/c echo %d'!A1", i))
	}
	line := []byte(strings.Join(cells, ","))
	res := &Result{}
	scanCSVLine(line, res, time.Time{})
	got := countPrefix(res.Streams, "CSV-DDE ")
	if got != maxCSVDDEMarkers {
		t.Errorf("scanCSVLine CSV-DDE count = %d, want %d", got, maxCSVDDEMarkers)
	}
}

// ─── Fix 3: OOXML-EXTERNAL-REL cap ───────────────────────────────────────────

// buildOOXMLWithManyRels creates an OOXML zip with a single .rels file
// containing n External relationships with suspicious http:// targets.
func buildOOXMLWithManyRels(t *testing.T, n int) []byte {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb,
			`<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://evil.test/%d" TargetMode="External"/>`,
			i, i)
	}
	sb.WriteString(`</Relationships>`)
	return makeOOXMLWithRels(t, sb.String())
}

// TestExternalRelsCapFires verifies fromOOXMLRels stops at maxExternalRels.
func TestExternalRelsCapFires(t *testing.T) {
	data := buildOOXMLWithManyRels(t, maxExternalRels+5)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLRels(zr, &out, time.Time{})
	got := countPrefix(out, "OOXML-EXTERNAL-REL ")
	if got != maxExternalRels {
		t.Errorf("OOXML-EXTERNAL-REL count = %d, want %d", got, maxExternalRels)
	}
}

// TestExternalRelsBelowCapPassesThrough verifies cap-1 rels all pass through.
func TestExternalRelsBelowCapPassesThrough(t *testing.T) {
	n := maxExternalRels - 1
	data := buildOOXMLWithManyRels(t, n)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLRels(zr, &out, time.Time{})
	got := countPrefix(out, "OOXML-EXTERNAL-REL ")
	if got != n {
		t.Errorf("OOXML-EXTERNAL-REL count = %d, want %d", got, n)
	}
}

// ─── Fix 4: OOXML-DDE-FIELD cap ──────────────────────────────────────────────

// buildWordXMLWithDDEFields builds a minimal word/document.xml containing n
// w:fldSimple DDE field instructions.
func buildWordXMLWithDDEFields(n int) []byte {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`)
	sb.WriteString(`<w:body>`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb,
			`<w:p><w:fldSimple w:instr="DDE cmd '/c echo %d' A1"/></w:p>`, i)
	}
	sb.WriteString(`</w:body></w:document>`)
	return []byte(sb.String())
}

// buildOOXMLWithDDEFields creates an OOXML zip with one document.xml containing n DDE fields.
func buildOOXMLWithDDEFields(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	addZipEntry(t, zw, "word/document.xml", string(buildWordXMLWithDDEFields(n)))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestDDEFieldsCapFires verifies fromOOXMLDDE stops at maxDDEFields.
func TestDDEFieldsCapFires(t *testing.T) {
	data := buildOOXMLWithDDEFields(t, maxDDEFields+5)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLDDE(zr, &out, time.Time{})
	got := countPrefix(out, "OOXML-DDE-FIELD ")
	if got != maxDDEFields {
		t.Errorf("OOXML-DDE-FIELD count = %d, want %d", got, maxDDEFields)
	}
}

// TestDDEFieldsBelowCapPassesThrough verifies cap-1 fields all pass through.
func TestDDEFieldsBelowCapPassesThrough(t *testing.T) {
	n := maxDDEFields - 1
	data := buildOOXMLWithDDEFields(t, n)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	fromOOXMLDDE(zr, &out, time.Time{})
	got := countPrefix(out, "OOXML-DDE-FIELD ")
	if got != n {
		t.Errorf("OOXML-DDE-FIELD count = %d, want %d", got, n)
	}
}

// ─── Benchmark: XLSB DDE cap (O(1) counter should be flat) ──────────────────

// BenchmarkXLSBDDECap200 checks that processing 200 DDE records (well above
// cap) is O(1) in counter overhead — the inner loop exits at maxXLSBSupBookDDE.
func BenchmarkXLSBDDECap200(b *testing.B) {
	raw := buildXLSBStream(200)
	data := buildXLSBZip(b, raw)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out [][]byte
		fromXLSBExternalDDE(zr, &out, time.Time{})
	}
}
