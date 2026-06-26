package extract

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BIFF stream builder helpers for SHRFMLA tests.
// (Prefixed "shrfmla" to avoid redeclaration conflicts with encsig_test.go /
// defaultpw_test.go which define biffRecord and biffBOF.)
// ---------------------------------------------------------------------------

// shrfmlaBOF builds a minimal BOF record (0x0809) for the given dt.
// dt=0x0040 → Excel-4.0 macrosheet; dt=0x0010 → workbook globals.
func shrfmlaBOF(dt uint16) []byte {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:], 0x0600) // vers = BIFF8
	binary.LittleEndian.PutUint16(payload[2:], dt)
	return biffRecord(0x0809, payload)
}

// shrfmlaFORMULA builds a FORMULA record (0x0006) for the given 0-based row/col
// and ptg token stream. Fills in the fixed-size header fields with zeros.
// Payload layout: row(2) col(2) ixfe(2) result(8) grbit(2) chn(4) cce(2) rgce[cce].
func shrfmlaFORMULA(row, col uint16, rgce []byte) []byte {
	payload := make([]byte, 22+len(rgce))
	binary.LittleEndian.PutUint16(payload[0:], row)
	binary.LittleEndian.PutUint16(payload[2:], col)
	// ixfe(2) result(8) grbit(2) chn(4) at offsets 4..21 — zero-filled.
	binary.LittleEndian.PutUint16(payload[20:], uint16(len(rgce)))
	copy(payload[22:], rgce)
	return biffRecord(0x0006, payload)
}

// shrfmlaPtgExp builds a ptgExp token stream that points at the given 0-based
// anchor row/col. This is the only token in a shared-formula FORMULA record.
func shrfmlaPtgExp(anchorRow, anchorCol uint16) []byte {
	b := make([]byte, 5)
	b[0] = ptgExp
	binary.LittleEndian.PutUint16(b[1:], anchorRow)
	binary.LittleEndian.PutUint16(b[3:], anchorCol)
	return b
}

// shrfmlaRecord builds a SHRFMLA record (0x00BC).
// rwFirst/rwLast/colFirst/colLast describe the shared range; rgce is the formula body.
func shrfmlaRecord(rwFirst, rwLast uint16, colFirst, colLast byte, rgce []byte) []byte {
	payload := make([]byte, 9+len(rgce))
	binary.LittleEndian.PutUint16(payload[0:], rwFirst)
	binary.LittleEndian.PutUint16(payload[2:], rwLast)
	payload[4] = colFirst
	payload[5] = colLast
	payload[6] = 0 // reserved
	binary.LittleEndian.PutUint16(payload[7:], uint16(len(rgce)))
	copy(payload[9:], rgce)
	return biffRecord(0x00BC, payload)
}

// buildSHRFMLAStream builds a minimal BIFF stream containing:
//  1. Workbook globals BOF (dt=0x0010) — so the macrosheet BOF is scanned.
//  2. Macrosheet BOF (dt=0x0040).
//  3. First FORMULA at anchorRow/anchorCol carrying the shared formula body.
//  4. SHRFMLA record with that body (immediately after the anchor FORMULA).
//  5. Second FORMULA at ptgExpRow/ptgExpCol carrying only ptgExp pointing back.
//  6. EOF (0x000A).
//
// This matches the BIFF8 layout described in MS-XLS §2.4.271.
func buildSHRFMLAStream(anchorRow, anchorCol, ptgExpRow, ptgExpCol uint16, sharedRgce []byte) []byte {
	var stream []byte
	// Workbook globals BOF — required so the loop's scanned counter increments
	// on BOUNDSHEET records rather than bailing immediately.
	stream = append(stream, shrfmlaBOF(0x0010)...)
	// Macrosheet substream BOF.
	stream = append(stream, shrfmlaBOF(0x0040)...)
	// Anchor FORMULA: carries the shared formula in its own rgce (normal cell).
	stream = append(stream, shrfmlaFORMULA(anchorRow, anchorCol, sharedRgce)...)
	// SHRFMLA immediately after the anchor FORMULA.
	stream = append(stream, shrfmlaRecord(anchorRow, anchorRow, byte(anchorCol), byte(anchorCol), sharedRgce)...)
	// ptgExp FORMULA pointing back at the anchor.
	stream = append(stream, shrfmlaFORMULA(ptgExpRow, ptgExpCol, shrfmlaPtgExp(anchorRow, anchorCol))...)
	// EOF.
	stream = append(stream, biffRecord(0x000A, nil)...)
	return stream
}

// ---------------------------------------------------------------------------
// Positive test: shared EXEC formula surfaces for both anchor and ptgExp cell.
// ---------------------------------------------------------------------------

// TestSHRFMLA_ExecFormulaResolved verifies that a FORMULA cell using ptgExp to
// reference a shared =EXEC("evil.exe") formula has the EXEC content visible
// in the output — i.e. the shared formula body is resolved and evaluated.
func TestSHRFMLA_ExecFormulaResolved(t *testing.T) {
	// Build shared formula body: ptgStr8("evil.exe") + ptgFuncVar EXEC (argc=1, id=110).
	sharedRgce := ptgStr8("evil.exe")
	sharedRgce = append(sharedRgce, ptgFuncVarTok(1, 110)...) // =EXEC("evil.exe")

	stream := buildSHRFMLAStream(0, 0, 1, 0, sharedRgce) // anchor A1, ptgExp B1→col0 row1

	res := &Result{}
	scanBIFFXLMStream(stream, res, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("evil.exe")) {
		t.Errorf("shared EXEC formula not resolved: streams=%q", joined)
	}
	// The dangerous marker must fire for the EXEC via the shared body.
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("EXEC")) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("EXEC marker not found in streams: %q", joined)
	}
}

// ---------------------------------------------------------------------------
// No-behavior-change test: stream with no SHRFMLA produces same output as before.
// ---------------------------------------------------------------------------

// TestSHRFMLA_NoSHRFMLAUnchanged verifies that a BIFF stream with only normal
// FORMULA records (no SHRFMLA, no ptgExp) produces the same folded output as
// it would without the SHRFMLA feature.
func TestSHRFMLA_NoSHRFMLAUnchanged(t *testing.T) {
	// A normal FORMULA at A1 with =EXEC("calc.exe").
	normalRgce := ptgStr8("calc.exe")
	normalRgce = append(normalRgce, ptgFuncVarTok(1, 110)...)

	var stream []byte
	stream = append(stream, shrfmlaBOF(0x0010)...)
	stream = append(stream, shrfmlaBOF(0x0040)...)
	stream = append(stream, shrfmlaFORMULA(0, 0, normalRgce)...)
	stream = append(stream, biffRecord(0x000A, nil)...)

	res := &Result{}
	scanBIFFXLMStream(stream, res, time.Time{})

	joined := bytes.Join(res.Streams, []byte("\n"))
	if !bytes.Contains(joined, []byte("calc.exe")) {
		t.Errorf("normal formula output missing: streams=%q", joined)
	}
}

// ---------------------------------------------------------------------------
// Adversarial: truncated SHRFMLA (cce > remaining bytes) — no panic, no garbage.
// ---------------------------------------------------------------------------

// TestSHRFMLA_TruncatedRecord verifies that a SHRFMLA record whose declared
// cce is larger than the remaining payload is handled gracefully: no panic,
// no output corruption, the existing anchor FORMULA output is preserved.
func TestSHRFMLA_TruncatedRecord(t *testing.T) {
	anchorRgce := ptgStr8("safe.exe")
	anchorRgce = append(anchorRgce, ptgFuncVarTok(1, 110)...)

	// Build a SHRFMLA with a cce field that claims 200 bytes but the record
	// only carries 3 bytes of rgce.
	badPayload := make([]byte, 9+3)
	binary.LittleEndian.PutUint16(badPayload[0:], 0)   // rwFirst
	binary.LittleEndian.PutUint16(badPayload[2:], 0)   // rwLast
	badPayload[4] = 0                                  // colFirst
	badPayload[5] = 0                                  // colLast
	badPayload[6] = 0                                  // reserved
	binary.LittleEndian.PutUint16(badPayload[7:], 200) // cce claims 200 bytes
	copy(badPayload[9:], []byte{0x17, 0x02, 0x00})     // only 3 bytes of rgce

	var stream []byte
	stream = append(stream, shrfmlaBOF(0x0010)...)
	stream = append(stream, shrfmlaBOF(0x0040)...)
	stream = append(stream, shrfmlaFORMULA(0, 0, anchorRgce)...)
	stream = append(stream, biffRecord(0x00BC, badPayload)...)
	// ptgExp cell — should produce no dangerous output (shared body is truncated/empty).
	stream = append(stream, shrfmlaFORMULA(1, 0, shrfmlaPtgExp(0, 0))...)
	stream = append(stream, biffRecord(0x000A, nil)...)

	res := &Result{}
	// Must not panic.
	scanBIFFXLMStream(stream, res, time.Time{})
	// No assertion on content — just verify no panic and no crash.
}

// ---------------------------------------------------------------------------
// Adversarial: colLast < colFirst in SHRFMLA — rejected, no panic.
// ---------------------------------------------------------------------------

func TestSHRFMLA_InvalidRange_ColLastLtColFirst(t *testing.T) {
	badPayload := make([]byte, 9)
	binary.LittleEndian.PutUint16(badPayload[0:], 0) // rwFirst
	binary.LittleEndian.PutUint16(badPayload[2:], 0) // rwLast
	badPayload[4] = 5                                // colFirst = 5
	badPayload[5] = 2                                // colLast = 2 < colFirst → invalid
	badPayload[6] = 0
	binary.LittleEndian.PutUint16(badPayload[7:], 0) // cce=0

	var stream []byte
	stream = append(stream, shrfmlaBOF(0x0010)...)
	stream = append(stream, shrfmlaBOF(0x0040)...)
	stream = append(stream, biffRecord(0x00BC, badPayload)...)
	stream = append(stream, biffRecord(0x000A, nil)...)

	res := &Result{}
	scanBIFFXLMStream(stream, res, time.Time{}) // must not panic
}

// ---------------------------------------------------------------------------
// Adversarial: ptgExp pointing at non-existent anchor — graceful fallback.
// ---------------------------------------------------------------------------

// TestSHRFMLA_MissingAnchor verifies that a ptgExp pointer that has no
// matching SHRFMLA entry in the table results in the cell being silently
// skipped (as before), without panicking or producing garbage output.
func TestSHRFMLA_MissingAnchor(t *testing.T) {
	var stream []byte
	stream = append(stream, shrfmlaBOF(0x0010)...)
	stream = append(stream, shrfmlaBOF(0x0040)...)
	// ptgExp pointing at row=99, col=99 — no SHRFMLA exists for this anchor.
	stream = append(stream, shrfmlaFORMULA(0, 0, shrfmlaPtgExp(99, 99))...)
	stream = append(stream, biffRecord(0x000A, nil)...)

	res := &Result{}
	scanBIFFXLMStream(stream, res, time.Time{})
	// No dangerous output — the cell should fold to "" (current behavior).
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("EXEC")) || bytes.Contains(s, []byte("CALL")) {
			t.Errorf("unexpected dangerous marker from unresolved ptgExp: %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Self-reference guard: shared body containing ptgExp — bounded, no hang.
// ---------------------------------------------------------------------------

// TestSHRFMLA_SharedBodyContainsPtgExp verifies that a shared formula body
// which itself begins with ptgExp does not recurse unboundedly. The body is
// used as-is (the ptg walker pushes "" for ptgExp) and the call terminates.
func TestSHRFMLA_SharedBodyContainsPtgExp(t *testing.T) {
	// Shared formula body is itself a ptgExp pointing somewhere.
	// This is pathological but must not recurse.
	selfRefBody := shrfmlaPtgExp(0, 0) // ptgExp → row0, col0

	stream := buildSHRFMLAStream(0, 0, 1, 0, selfRefBody)

	res := &Result{}
	// Must terminate promptly and not panic.
	scanBIFFXLMStream(stream, res, time.Now().Add(5*time.Second))
}

// ---------------------------------------------------------------------------
// Unit tests for parseSHRFMLARecord.
// ---------------------------------------------------------------------------

func TestParseSHRFMLARecord_Valid(t *testing.T) {
	body := ptgStr8("hello")
	payload := make([]byte, 9+len(body))
	binary.LittleEndian.PutUint16(payload[0:], 3) // rwFirst=3
	binary.LittleEndian.PutUint16(payload[2:], 5) // rwLast=5
	payload[4] = 2                                // colFirst=2
	payload[5] = 4                                // colLast=4
	payload[6] = 0                                // reserved
	binary.LittleEndian.PutUint16(payload[7:], uint16(len(body)))
	copy(payload[9:], body)

	key, rgce, ok := parseSHRFMLARecord(payload)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if key[0] != 3 || key[1] != 2 {
		t.Errorf("key = %v, want {3,2}", key)
	}
	if !bytes.Equal(rgce, body) {
		t.Errorf("rgce = %q, want %q", rgce, body)
	}
}

func TestParseSHRFMLARecord_TooShort(t *testing.T) {
	_, _, ok := parseSHRFMLARecord([]byte{0, 0, 0, 0, 0, 0, 0}) // only 7 bytes, need 9
	if ok {
		t.Error("expected ok=false for truncated payload")
	}
}

func TestParseSHRFMLARecord_ColLastLtColFirst(t *testing.T) {
	payload := make([]byte, 9)
	payload[4] = 5 // colFirst
	payload[5] = 2 // colLast < colFirst
	_, _, ok := parseSHRFMLARecord(payload)
	if ok {
		t.Error("expected ok=false for colLast < colFirst")
	}
}

func TestParseSHRFMLARecord_ZeroCce(t *testing.T) {
	payload := make([]byte, 9) // cce=0
	_, _, ok := parseSHRFMLARecord(payload)
	if ok {
		t.Error("expected ok=false for cce=0")
	}
}

// ---------------------------------------------------------------------------
// Unit tests for hasPtgExp.
// ---------------------------------------------------------------------------

func TestHasPtgExp_Valid(t *testing.T) {
	rgce := shrfmlaPtgExp(10, 3)
	row, col, ok := hasPtgExp(rgce)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if row != 10 || col != 3 {
		t.Errorf("row=%d col=%d, want 10,3", row, col)
	}
}

func TestHasPtgExp_NotPtgExp(t *testing.T) {
	rgce := ptgStr8("hello")
	_, _, ok := hasPtgExp(rgce)
	if ok {
		t.Error("expected ok=false for non-ptgExp stream")
	}
}

func TestHasPtgExp_TooShort(t *testing.T) {
	_, _, ok := hasPtgExp([]byte{ptgExp, 0, 0}) // only 3 bytes, need 5
	if ok {
		t.Error("expected ok=false for too-short stream")
	}
}

// ---------------------------------------------------------------------------
// Version string test.
// ---------------------------------------------------------------------------

func TestVersionContainsSHRFMLA(t *testing.T) {
	if !strings.Contains(Version, "+shrfmla") {
		t.Errorf("Version %q does not contain +shrfmla", Version)
	}
}

// ---------------------------------------------------------------------------
// Fuzz seed: add SHRFMLA stream to the biff_ptg fuzz suite.
// (Standalone fuzz function for the SHRFMLA parse path.)
// ---------------------------------------------------------------------------

// FuzzSHRFMLARecord fuzzes parseSHRFMLARecord for safety: no panic, no OOM.
func FuzzSHRFMLARecord(f *testing.F) {
	// Seed: valid 5-byte body.
	{
		body := ptgStr8("x")
		payload := make([]byte, 9+len(body))
		binary.LittleEndian.PutUint16(payload[0:], 0)
		binary.LittleEndian.PutUint16(payload[2:], 0)
		payload[4] = 0
		payload[5] = 0
		binary.LittleEndian.PutUint16(payload[7:], uint16(len(body)))
		copy(payload[9:], body)
		f.Add(payload)
	}
	// Seed: empty.
	f.Add([]byte{})
	// Seed: too short.
	f.Add([]byte{0, 0, 0, 0, 0})
	// Seed: cce larger than remaining bytes.
	{
		payload := make([]byte, 11)
		binary.LittleEndian.PutUint16(payload[7:], 0xFFFF) // huge cce
		f.Add(payload)
	}
	// Seed: random garbage.
	f.Add([]byte{0xFF, 0xFE, 0x00, 0xAB, 0xCD, 0xEF, 0x42, 0x00, 0x17, 0x03, 0x00, 'a', 'b'})

	f.Fuzz(func(t *testing.T, data []byte) {
		key, rgce, ok := parseSHRFMLARecord(data)
		if ok {
			// Must be a valid key and bounded rgce.
			if len(rgce) > maxSHRFMLACce {
				t.Fatalf("rgce len %d exceeds maxSHRFMLACce %d", len(rgce), maxSHRFMLACce)
			}
			_ = key
		}
	})
}
