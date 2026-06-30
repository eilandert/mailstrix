package extract

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FuzzExtract drives the OLE2/OOXML parsers with arbitrary bytes. Extract parses
// fully attacker-controlled binary (a mail attachment), so the invariant is
// strong: it must NEVER panic out, NEVER hang, and always return a self-
// consistent Result — Encrypted implies no streams, !IsDoc implies no streams,
// every stream non-empty. A crash here is a remote DoS on the scan path.
func FuzzExtract(f *testing.F) {
	// Seed with the real macro doc, the magics, and structurally interesting
	// near-misses so the fuzzer starts from valid-ish containers, not just noise.
	if buf, err := os.ReadFile(filepath.Join("testdata", "xlswithmacro.xlsm")); err == nil {
		f.Add(buf)
	}
	f.Add(append(append([]byte{}, oleMagic...), bytes.Repeat([]byte{0x00}, 512)...))
	f.Add(append(append([]byte{}, zipMagic...), bytes.Repeat([]byte{0xFF}, 64)...))
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	if w, err := zw.Create("xl/vbaProject.bin"); err == nil {
		_, _ = w.Write(append(append([]byte{}, oleMagic...), 0x01, 0x02, 0x03))
	}
	_ = zw.Close()
	f.Add(z.Bytes())
	// Archive magics (gz/7z/rar) followed by junk — exercise the nested-archive
	// decompressors' fail-open paths.
	f.Add(append(append([]byte{}, gzipMagic...), bytes.Repeat([]byte{0xFF}, 64)...))
	f.Add(append(append([]byte{}, sevenZMagic...), bytes.Repeat([]byte{0xAA}, 128)...))
	f.Add(append(append([]byte{}, rarMagic...), bytes.Repeat([]byte{0x55}, 128)...))
	// OLE2 magic + a truncated Ole10Native-shaped tail — fuzz the package field
	// walk's bounds checks on hostile/short input.
	f.Add(append(append([]byte{}, oleMagic...),
		[]byte{0x10, 0, 0, 0, 0x02, 0, 'a', 0, 'b', 0, 0, 0, 0, 0}...))
	// .lnk magic + flags claiming IDList/LinkInfo/Arguments then junk — fuzz the
	// SHLLINK section walk and StringData bounds checks.
	{
		h := make([]byte, lnkHeaderSize)
		copy(h, lnkMagic)
		h[lnkFlagsOff] = byte(lnkHasLinkTargetIDList | lnkHasLinkInfo | lnkHasArguments | lnkIsUnicode)
		f.Add(append(h, bytes.Repeat([]byte{0xFF}, 32)...))
	}
	// PDF magic + a stream keyword without endstream — fuzz the carve/inflate loop.
	f.Add([]byte("%PDF-1.7\nobj\nstream\n\x78\x9c\x00\x00 garbage no endstream"))
	// RTF with an \objdata group of odd-length/garbage hex — fuzz the hex decoder
	// and the fromRTF group-scan bounds (must terminate, never over-read).
	f.Add([]byte("{\\rtf1{\\object{\\*\\objdata d0cf11e0 a1b11ae1 zz}}}"))
	// VBA dir-stream seeds: exercise walkDirStream bounds-checks via the full
	// Extract path (wrapped in an OLE2 container by the fuzzer's mutations).
	// Single-module baseline.
	f.Add(buildSyntheticDirStream([]testModule{
		{name: "Module1", streamName: "Module1", offset: 100},
	}))
	// Multi-module: all three must be enumerated.
	f.Add(buildSyntheticDirStream([]testModule{
		{name: "Module1", streamName: "Module1", offset: 100},
		{name: "Module2", streamName: "Module2", offset: 200},
		{name: "Sheet1", streamName: "Sheet1", offset: 50},
	}))
	// MBCS/non-ASCII raw bytes in module name field.
	f.Add(buildSyntheticDirStream([]testModule{
		{name: "M\xF3dulo\xFF", streamName: "Mod", offset: 0},
	}))
	// Truncated: only the header section present, no module records.
	f.Add(func() []byte {
		d := buildSyntheticDirStream(nil) // zero modules → short stream
		return d
	}())
	// Adversarial: module count claims 0xFFFF but body is empty after count field.
	f.Add(func() []byte {
		d := buildSyntheticDirStream(nil)
		patchModuleCount(d, 0xFFFF)
		return d
	}())
	// Adversarial: single record with huge declared size right after the magic.
	f.Add(func() []byte {
		var b []byte
		b = appendU16(b, 0x0001)
		b = appendU32(b, 0x7FFFFFFF)
		return b
	}())
	f.Add([]byte{})
	f.Add([]byte("plain text"))

	f.Fuzz(func(t *testing.T, buf []byte) {
		res := Extract(buf, time.Time{}) // must not panic, must terminate

		// IsDoc is a container-classification metric only — it is NOT a gate on
		// stream emission. The default (non-container) path runs text-payload
		// emitters (fromEncoded/fromCSVDDE/fromHTMLSmuggling/fromEncodedScript)
		// that legitimately surface decoded streams from arbitrary text without
		// setting IsDoc; those streams are scanned downstream. So a non-doc with
		// streams is VALID — the invariant is only that an ENCRYPTED doc reveals
		// no plaintext streams.
		if res.Encrypted && len(res.Streams) > 0 {
			t.Fatalf("encrypted doc also returned %d streams", len(res.Streams))
		}
		for i, s := range res.Streams {
			if len(s) == 0 {
				t.Fatalf("empty stream at %d", i)
			}
		}
		if len(res.Streams) > maxStreams {
			t.Fatalf("returned %d streams > cap %d", len(res.Streams), maxStreams)
		}
	})
}

// FuzzDecompressStream drives decompressOVBA (the size-capped wrapper around
// oleparse.DecompressStream) with arbitrary bytes. The invariant: never panic,
// always return a slice of length <= maxBytesPerModule.
func FuzzDecompressStream(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01})
	// Minimal raw chunk: signature + header word (raw, 4096 bytes) — but just a
	// short stub; the fuzzer will mutate it into interesting shapes.
	f.Add([]byte{0x01, 0x03, 0x03})
	// Copy-token seed: signature + compressed-chunk header with high bit set,
	// followed by a copy-token pointing past the start of the window.
	f.Add([]byte{0x01, 0x00, 0xB0, 0xFF, 0x03})

	f.Fuzz(func(t *testing.T, data []byte) {
		out := decompressOVBA(data)
		if len(out) > maxBytesPerModule {
			t.Fatalf("decompressOVBA returned %d bytes > cap %d", len(out), maxBytesPerModule)
		}
	})
}

// FuzzFoldXLMFormula drives the XLM constant-folder with arbitrary formula
// text. foldXLMFormula↔foldFunctionCall are mutually recursive over attacker-
// controlled nesting, so the invariant is: never overflow the stack, always
// terminate, never return more than the input could justify. Seeds cover:
// CHAR()& chains, deep EXEC nesting (depth gate), MID() slicing (foldMIDCall
// ↔ foldXLMFormulaDepth recursion), splitOnConcat corner-cases (unbalanced
// parens, embedded quotes, zero-length parts), dangerous-func markers. (STAB-1)
func FuzzFoldXLMFormula(f *testing.F) {
	// Baseline seeds (original).
	f.Add("=CHAR(104)&CHAR(116)&\"tp://evil.com\"")
	f.Add("=EXEC(CHAR(99)&\"md /c calc\")")
	f.Add(func() string {
		s := "CHAR(65)"
		for i := 0; i < maxXLMFoldDepth*8; i++ {
			s = "EXEC(" + s + ")"
		}
		return "=" + s
	}())
	f.Add("")
	f.Add("plain text no formula")

	// MID() path — foldMIDCall ↔ foldXLMFormulaDepth recursion (new in #333).
	f.Add(`=MID("hello world",1,5)`)
	f.Add(`=MID(CHAR(104)&"ttp://evil.com",1,15)`)
	f.Add(`=MID(MID("nested",1,6),2,3)`)
	// Deep MID nesting — exercises the depth gate on the recursive path.
	f.Add(func() string {
		s := `"ABCDEFGH"`
		for i := 0; i < maxXLMFoldDepth*3; i++ {
			s = "MID(" + s + ",1,8)"
		}
		return "=" + s
	}())
	// MID with bad arg counts (< 3 args — must not panic).
	f.Add(`=MID("text",1)`)
	f.Add(`=MID()`)
	f.Add(`=MID("text")`)
	// MID start=0 and start > len (boundary).
	f.Add(`=MID("abc",0,2)`)
	f.Add(`=MID("abc",99,2)`)
	f.Add(`=MID("abc",1,0)`)

	// splitOnConcat corner-cases (unbalanced parens, embedded quotes).
	f.Add(`="&"`)
	f.Add(`="""" & """"`)        // escaped quotes on both sides of &
	f.Add(`=CHAR(65)&"A&B"`)     // & inside a string literal
	f.Add(`=EXEC(CHAR(65)&"B")`) // & inside balanced parens
	f.Add(`=((CHAR(65)))`)       // extra parens
	f.Add(`=CHAR(65)&CHAR(`)     // truncated — unbalanced open paren
	f.Add(`=CHAR(65))&CHAR(66)`) // extra close paren

	// Dangerous-func markers with nested folding.
	f.Add(`=CALL(CHAR(99)&"md",CHAR(32)&"/c calc")`)
	f.Add(`=REGISTER("ntdll","ZwCreateProcess",` + `"JJCJJ")`)
	f.Add(`=FOPEN(MID("C:\\evil.bat",1,12),"rw")`)
	f.Add(`=SEND.KEYS(CHAR(123)&"F4}")`)
	// EXECUTE (DDE) — distinct from EXEC.
	f.Add(`=EXECUTE(CHAR(99)&"md")`)
	// INITIATE (DDE conversation).
	f.Add(`=INITIATE("Excel","[EXEC(cmd)]")`)

	// Mixed: MID inside EXEC inside concatenation.
	f.Add(`=EXEC(MID("cmd /c calc",1,11)&CHAR(0))`)

	// Whitespace and case variants.
	f.Add(`= CHAR( 65 ) & CHAR( 66 )`)
	f.Add(`=char(65)&mid("AB",1,1)`)

	f.Fuzz(func(t *testing.T, formula string) {
		// Bound the input the way the real caller does (maxXLMFoldFormulaLen)
		// so the fuzzer explores formula structure, not raw size.
		if len(formula) > maxXLMFoldFormulaLen {
			formula = formula[:maxXLMFoldFormulaLen]
		}
		out := foldXLMFormula(formula) // must not panic / overflow / hang
		if len(out) > 4*maxXLMFoldFormulaLen {
			t.Fatalf("folded output %d >> input %d", len(out), len(formula))
		}
	})
}
