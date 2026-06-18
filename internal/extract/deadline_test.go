package extract

import (
	"testing"
	"time"
)

// TestExtractDeadlineStopsPerFormat asserts the per-request scan deadline is
// honored by EVERY extractor loop, not only fromOLE/fromOOXML/fromArchive.
// Extraction runs inside the held scan-CPU slot, so an already-expired deadline
// must short-circuit each format before doing carve/inflate work — otherwise a
// CPU-heavy hostile document could overrun the wall-clock budget the scanner
// promises. For each format: a live deadline yields ≥1 stream (the fixture is
// real), an expired deadline yields none.
func TestExtractDeadlineStopsPerFormat(t *testing.T) {
	// VBE: the canonical screnc block from script_test.go (decodes to one stream).
	vbe := []byte(
		"#@~^DgAAAA==" +
			"\x5c\x6b\x6f\x24\x4b\x36\x2c\x4a\x43\x7f\x56\x5e\x47\x4a\x71\x41\x51\x41\x41\x41\x3d\x3d" +
			"^#~@",
	)

	cases := []struct {
		name string
		buf  []byte
	}{
		{"pdf", pdfWithStream(zlibDeflate([]byte("/JS app.alert(1) /OpenAction")))},
		{"rtf", wrapRTFObjData(buildOle10Native("evil.exe", "evil.exe", "C:\\tmp\\evil.exe", []byte("MZ rtf-dropped payload"), 0))},
		{"onenote", buildOneNote(buildFDSO([]byte("MZ onenote payload"), 0))},
		{"msi", buildMinimalMSI(t, []byte("CustomAction powershell -enc ABCD; "))},
		{"vbe", vbe},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			live := Extract(tc.buf, time.Now().Add(10*time.Second))
			if len(live.Streams) == 0 {
				t.Fatalf("%s fixture yielded no streams under a live deadline (bad fixture)", tc.name)
			}
			past := Extract(tc.buf, time.Now().Add(-time.Second))
			if len(past.Streams) != 0 {
				t.Errorf("%s: expired deadline still produced %d streams", tc.name, len(past.Streams))
			}
		})
	}
}
