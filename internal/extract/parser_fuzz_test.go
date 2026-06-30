package extract

import (
	"bytes"
	"testing"
	"time"
)

// This file fuzzes the format-specific extractors DIRECTLY, bypassing the magic
// dispatch in Extract(). FuzzExtract reaches them too, but it spends most of its
// energy mutating the outer dispatch byte; calling fromPDF/fromRTF/… directly
// lets the fuzzer drive the deep parser structure. Every target shares the same
// invariants: never panic, always terminate, emit no empty stream, respect the
// maxStreams cap. The parsers are fail-open (recover internally), so a crash
// surfaced here is a real remote-DoS bug on an attacker-controlled attachment.

// checkResult asserts the shared post-extraction invariants on a Result.
func checkResult(t *testing.T, res *Result) {
	t.Helper()
	for i, s := range res.Streams {
		if len(s) == 0 {
			t.Fatalf("empty stream at %d", i)
		}
	}
	if len(res.Streams) > maxStreams {
		t.Fatalf("returned %d streams > cap %d", len(res.Streams), maxStreams)
	}
}

// fuzzDeadline gives each parser a short wall-clock budget so a pathological
// input that loops on the deadline check still terminates the fuzz exec quickly.
func fuzzDeadline() time.Time { return time.Now().Add(2 * time.Second) }

// FuzzPDF drives the PDF object/stream carver + indicator pass with hostile
// bytes behind the %PDF- magic.
func FuzzPDF(f *testing.F) {
	f.Add([]byte("%PDF-1.7\n"))
	f.Add([]byte("%PDF-1.7\nobj\nstream\n\x78\x9c\x00\x00 garbage no endstream"))
	f.Add([]byte("%PDF-1.4\n1 0 obj<</Filter/FlateDecode/Length 99>>stream\n\x78\x9cxxxxendstream endobj"))
	f.Add([]byte("%PDF-1.5\n/JavaScript (app.alert\\(1\\)) /OpenAction <</S/JavaScript>>"))
	f.Add([]byte("%PDF-1.7\n" + "stream\nendstream\n" + "stream\nendstream\n"))
	f.Add(append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte{0xFF}, 256)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		opts := FullOptions(fuzzDeadline())
		res.childOpts = opts
		fromPDF(buf, &res, opts)
		checkResult(t, &res)
	})
}

// FuzzRTF drives the RTF \objdata hex-decode + embedded-object carve. The hex
// decoder and group scanner walk attacker-controlled nesting/odd-length hex.
func FuzzRTF(f *testing.F) {
	f.Add([]byte(`{\rtf1}`))
	f.Add([]byte(`{\rtf1{\object{\*\objdata d0cf11e0 a1b11ae1 zz}}}`))
	f.Add([]byte(`{\rtf1{\object\objemb{\*\objclass Package}{\*\objdata 01050000}}}`))
	f.Add([]byte(`{\rt` + `{\*\objdata ` + "ffff" + `}`)) // unbalanced group
	f.Add([]byte(`{\rtf1\bin5 \x00\x01\x02\x03\x04 trailing}`))
	f.Add(append([]byte(`{\rtf1{\*\objdata `), bytes.Repeat([]byte("4d5a"), 200)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		bud := &archiveBudget{}
		fromRTF(buf, &res, bud, 0, fuzzDeadline())
		checkResult(t, &res)
	})
}

// FuzzLNK drives the ShellLinkHeader / IDList / LinkInfo / StringData walk. The
// section walk does many bounds checks on hostile length fields.
func FuzzLNK(f *testing.F) {
	mkHeader := func(flags byte) []byte {
		h := make([]byte, lnkHeaderSize)
		copy(h, lnkMagic)
		h[lnkFlagsOff] = flags
		return h
	}
	f.Add(mkHeader(0))
	f.Add(append(mkHeader(byte(lnkHasLinkTargetIDList|lnkHasLinkInfo|lnkHasArguments|lnkIsUnicode)),
		bytes.Repeat([]byte{0xFF}, 32)...))
	f.Add(append(mkHeader(byte(lnkHasArguments)),
		[]byte{0x05, 0x00, 'c', 0, 'a', 0, 'l', 0, 'c', 0}...))
	f.Add(lnkMagic) // header magic only, truncated
	f.Add(append(mkHeader(byte(lnkHasLinkTargetIDList)),
		[]byte{0xFF, 0xFF}...)) // IDList claiming 0xFFFF size

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		fromLNK(buf, &res)
		checkResult(t, &res)
	})
}

// FuzzTNEF drives the winmail.dat TLV attachment-object decoder.
func FuzzTNEF(f *testing.F) {
	tnefMagic := []byte{0x78, 0x9F, 0x3E, 0x22}
	f.Add(tnefMagic)
	f.Add(append(append([]byte{}, tnefMagic...), bytes.Repeat([]byte{0x00}, 64)...))
	// magic + version-LV + a truncated attribute TLV.
	f.Add(append(append([]byte{}, tnefMagic...),
		[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x90, 0x08, 0x00}...))
	f.Add(append(append([]byte{}, tnefMagic...), bytes.Repeat([]byte{0xFF}, 128)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		bud := &archiveBudget{}
		fromTNEF(buf, &res, bud, 0, fuzzDeadline())
		checkResult(t, &res)
	})
}

// FuzzOneNote drives the FileDataStoreObject carve out of a OneNote section.
func FuzzOneNote(f *testing.F) {
	f.Add(append([]byte{}, oneSectionGUID...))
	f.Add(append([]byte{}, oneTOCGUID...))
	f.Add(append(append([]byte{}, oneSectionGUID...), bytes.Repeat([]byte{0x00}, 64)...))
	f.Add(append(append([]byte{}, oneSectionGUID...), bytes.Repeat([]byte{0xFF}, 256)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		bud := &archiveBudget{}
		fromOneNote(buf, &res, bud, 0, fuzzDeadline())
		checkResult(t, &res)
	})
}

// FuzzSLK drives the SYLK C-record E-field formula fold (XLM/DDE carrier).
func FuzzSLK(f *testing.F) {
	f.Add([]byte("ID;P\n"))
	f.Add([]byte("ID;PWXL\nC;X1;Y1;E=cmd|'/c calc'!A1\nE\n"))
	f.Add([]byte("ID;P\nC;Y1;X1;K\"=EXEC(\"\nE\n"))
	f.Add([]byte("ID;" + string(bytes.Repeat([]byte("C;X1;E1+1\n"), 100))))
	f.Add(append([]byte("ID;"), bytes.Repeat([]byte{0xFF}, 128)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		fromSLK(buf, &res, fuzzDeadline())
		checkResult(t, &res)
	})
}

// FuzzEncodedScript drives the MS Script Encoder (#@~^…^#~@) decoder.
func FuzzEncodedScript(f *testing.F) {
	f.Add([]byte("#@~^"))
	f.Add([]byte("#@~^AAAAAA==^#~@"))
	f.Add([]byte("prefix #@~^BBBBBB==garbage^#~@ suffix"))
	f.Add([]byte("#@~^" + string(bytes.Repeat([]byte{0x7E}, 200))))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		fromEncodedScript(buf, &res, fuzzDeadline())
		checkResult(t, &res)
	})
}

// FuzzCSVDDE drives the CSV/TSV DDE command-injection cell detector.
func FuzzCSVDDE(f *testing.F) {
	f.Add([]byte("a,b,c\n1,2,3\n"))
	f.Add([]byte("=cmd|'/c calc'!A1,foo\n"))
	f.Add([]byte("@SUM(1+1)*cmd|'/c calc'!A0\n"))
	f.Add([]byte("+cmd|' /c notepad'!_xlbgnm.A1\t-2+3+cmd\n"))
	f.Add(append([]byte("=cmd|"), bytes.Repeat([]byte{0xFF}, 128)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		fromCSVDDE(buf, &res, fuzzDeadline())
		checkResult(t, &res)
	})
}

// FuzzHTMLSmuggling drives the HTML/SVG smuggling detector + data:-URI carve.
func FuzzHTMLSmuggling(f *testing.F) {
	f.Add([]byte("<html><body>hi</body></html>"))
	f.Add([]byte(`<a href="data:application/octet-stream;base64,TVqQAAMA" download="x.exe">x</a>`))
	f.Add([]byte(`<script>var b=atob("TVqQAAMA");new Blob([b]);</script>`))
	f.Add(append([]byte(`<a download href="data:;base64,`), bytes.Repeat([]byte("TVpQ"), 100)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		bud := &archiveBudget{}
		fromHTMLSmuggling(buf, &res, bud, 0, fuzzDeadline())
		checkResult(t, &res)
	})
}

// FuzzBatchDropper drives the .bat echo-redirect dropper carver.
func FuzzBatchDropper(f *testing.F) {
	f.Add([]byte("@echo off\n"))
	f.Add([]byte("echo malicious>%temp%\\x.vbs\ncscript %temp%\\x.vbs\n"))
	f.Add([]byte(">>a.ps1 echo IEX(New-Object Net.WebClient)\n"))
	f.Add(append([]byte("echo "), bytes.Repeat([]byte{0xFF}, 128)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var res Result
		bud := &archiveBudget{}
		fromBatchDropper(buf, &res, bud, 0, fuzzDeadline())
		checkResult(t, &res)
	})
}
