package extract

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// A real OOXML workbook with VBA macros must yield decompressed cleartext that
// the keyword rules can match. Every VBA module carries an `Attribute VB_Name`
// header once decompressed, so its presence proves the MS-OVBA decompress ran.
func TestExtractOOXMLMacro(t *testing.T) {
	buf := readFixture(t, "xlswithmacro.xlsm")
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Error("known .xlsm not flagged IsDoc")
	}
	if res.Failed || res.Panicked || res.Encrypted {
		t.Errorf("unexpected flags: %+v", flags(res))
	}
	if len(res.Streams) == 0 {
		t.Fatal("no macro streams extracted from a known-macro .xlsm")
	}
	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("Attribute VB_Name")) {
		t.Errorf("extracted streams missing decompressed VBA marker; got %dB", len(joined))
	}
}

// Non-container input (a plain mail body) must extract nothing and not be
// flagged a document — the scanner then sees only the raw bytes, exactly as
// before this package existed.
func TestExtractNonContainer(t *testing.T) {
	for _, in := range [][]byte{[]byte("a perfectly innocent email body"), nil, {0x00}, {'P', 'K'}} {
		res := Extract(in, time.Time{})
		if res.IsDoc || len(res.Streams) != 0 || res.Failed || res.Encrypted {
			t.Errorf("non-container %q yielded %+v", in, flags(res))
		}
	}
}

// OLE2 magic followed by garbage must fail open: IsDoc=true (magic matched) but
// no streams, Failed/Panicked recorded, no crash. This is the poison-document
// path — a malformed compound file must degrade to a raw-only scan.
func TestExtractMalformedOLEFailsOpen(t *testing.T) {
	buf := append(append([]byte{}, oleMagic...), bytes.Repeat([]byte{0xAB}, 4096)...)
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Error("OLE magic not flagged IsDoc")
	}
	if len(res.Streams) != 0 {
		t.Errorf("malformed OLE yielded streams: %v", res.Streams)
	}
	if !res.Failed {
		t.Error("malformed OLE not flagged Failed")
	}
}

// ZIP magic but not a valid archive must be flagged a doc-attempt that Failed;
// a valid zip with no .bin member is a doc with no streams and no failure.
func TestExtractZipNoMacro(t *testing.T) {
	bad := Extract(append(append([]byte{}, zipMagic...), 0x00, 0x01, 0x02), time.Time{})
	if !bad.IsDoc || !bad.Failed {
		t.Errorf("truncated zip: want IsDoc+Failed, got %+v", flags(bad))
	}

	ok := Extract(makeZip(t, "word/document.xml", "<xml/>"), time.Time{})
	if !ok.IsDoc {
		t.Error("valid .docx not flagged IsDoc")
	}
	if ok.Failed || len(ok.Streams) != 0 {
		t.Errorf("macro-free .docx: want no streams/failure, got %+v", flags(ok))
	}
}

// A .bin member that is not a real OLE2 compound file must be skipped without
// panicking. When it's the ONLY .bin and it fails, the whole doc is marked
// Failed (observable) rather than looking like a clean macro-free document.
func TestExtractOOXMLBadBinSkipped(t *testing.T) {
	res := Extract(makeZip(t, "word/vbaProject.bin", "not really an OLE file"), time.Time{})
	if !res.IsDoc || res.Panicked {
		t.Errorf("bad .bin: want IsDoc, no panic, got %+v", flags(res))
	}
	if len(res.Streams) != 0 {
		t.Errorf("bad .bin yielded streams: %v", res.Streams)
	}
	if !res.Failed {
		t.Errorf("all-bad .bin should be Failed (observable): %+v", flags(res))
	}
}

// An already-expired deadline must stop the OOXML extraction loop before doing
// the parse work, yielding no streams and a Failed flag — the bound that keeps a
// small compressed bomb from burning CPU ahead of the libyara scan budget.
func TestExtractOOXMLDeadlineStops(t *testing.T) {
	doc := readFixture(t, "xlswithmacro.xlsm")
	res := Extract(doc, time.Now().Add(-time.Second))
	if len(res.Streams) != 0 {
		t.Errorf("expired deadline still extracted %d streams", len(res.Streams))
	}
	if !res.Failed {
		t.Errorf("expired deadline should mark Failed: %+v", flags(res))
	}
}

// Version must be non-empty: it is folded into the verdict-cache fingerprint, so
// an empty value would silently disable extractor-version cache invalidation.
func TestVersionSet(t *testing.T) {
	if Version == "" {
		t.Error("extract.Version is empty")
	}
}

// codes() must bound the OLE2-path macro output three ways (ROBUST-BOUNDS), so a
// crafted vbaProject.bin can't OOM the container through res.Streams: per-module
// truncation, a stream-count cap, and a total-bytes cap across modules.
func TestCodesBounded(t *testing.T) {
	// One oversized module is truncated to maxBytesPerModule, not copied whole.
	huge := oleparse.VBAModule{Code: string(make([]byte, maxBytesPerModule+4096))}
	out := codes([]*oleparse.VBAModule{&huge}, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 stream, got %d", len(out))
	}
	if len(out[0]) != maxBytesPerModule {
		t.Errorf("module not clamped: got %d, want %d", len(out[0]), maxBytesPerModule)
	}

	// Thousands of modules can't exceed maxStreams blobs.
	many := make([]*oleparse.VBAModule, maxStreams+50)
	for i := range many {
		many[i] = &oleparse.VBAModule{Code: "x"}
	}
	if got := len(codes(many, nil)); got > maxStreams {
		t.Errorf("stream-count cap breached: got %d, want <= %d", got, maxStreams)
	}

	// Total bytes across modules can't exceed maxTotalCode. Each 1 MiB module,
	// enough of them to blow maxTotalCode well before maxStreams (256).
	big := make([]*oleparse.VBAModule, 64)
	for i := range big {
		big[i] = &oleparse.VBAModule{Code: string(make([]byte, 1<<20))}
	}
	out = codes(big, nil)
	total := 0
	for _, b := range out {
		total += len(b)
	}
	if total > maxTotalCode {
		t.Errorf("total-bytes cap breached: got %d, want <= %d", total, maxTotalCode)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func makeZip(t *testing.T, name, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func flags(r Result) map[string]any {
	return map[string]any{
		"IsDoc": r.IsDoc, "Encrypted": r.Encrypted,
		"Failed": r.Failed, "Panicked": r.Panicked, "streams": len(r.Streams),
	}
}
