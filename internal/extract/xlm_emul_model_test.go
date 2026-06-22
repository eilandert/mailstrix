package extract

import (
	"fmt"
	"testing"
	"time"
)

// newTestMachine is a helper that wires dummy sinks so tests don't need to
// manage output slices manually.
func newTestMachine() *xlmMachine {
	out := make([][]byte, 0)
	total := 0
	return newMachine(&out, &total, time.Time{}) // zero deadline → never expires
}

// TestSetCellGetCellValueRoundTrip stores a cell and reads it back.
func TestSetCellGetCellValueRoundTrip(t *testing.T) {
	m := newTestMachine()
	m.setCell("Sheet1", "A1", "=EXEC(\"calc.exe\")", "calc.exe")
	v, ok := m.getCellValue("Sheet1", "A1")
	if !ok {
		t.Fatal("expected cell to be found")
	}
	if v != "calc.exe" {
		t.Fatalf("got %q, want %q", v, "calc.exe")
	}
}

// TestSetCellNormalisesAbsoluteCoord verifies that $A$1 is stored and
// retrieved as A1.
func TestSetCellNormalisesAbsoluteCoord(t *testing.T) {
	m := newTestMachine()
	m.setCell("Sheet1", "$A$1", "", "hello")
	v, ok := m.getCellValue("Sheet1", "A1")
	if !ok {
		t.Fatal("expected normalised coord to be found")
	}
	if v != "hello" {
		t.Fatalf("got %q, want %q", v, "hello")
	}
}

// TestSetCellEnforcesCap verifies that adding more than maxEmulCells cells
// across a single sheet stores exactly maxEmulCells cells.
func TestSetCellEnforcesCap(t *testing.T) {
	m := newTestMachine()
	for i := 0; i < maxEmulCells+1; i++ {
		// Use row numbers 1..maxEmulCells+1 to generate unique coords.
		// Rows >9999999 are invalid; cap at 7 digits — use two columns to be safe.
		coord := fmt.Sprintf("A%d", i+1)
		m.setCell("Sheet1", coord, "", fmt.Sprintf("v%d", i))
	}
	got := m.totalCells()
	if got != maxEmulCells {
		t.Fatalf("totalCells = %d, want %d", got, maxEmulCells)
	}
}

// TestGetCellValueMissingSheet returns false for an unknown sheet.
func TestGetCellValueMissingSheet(t *testing.T) {
	m := newTestMachine()
	_, ok := m.getCellValue("NoSuchSheet", "A1")
	if ok {
		t.Fatal("expected false for missing sheet")
	}
}

// TestGetCellValueEmptyValue returns false when the cell exists but value is "".
func TestGetCellValueEmptyValue(t *testing.T) {
	m := newTestMachine()
	m.setCell("Sheet1", "B2", "=EXEC(\"cmd\")", "") // no value
	_, ok := m.getCellValue("Sheet1", "B2")
	if ok {
		t.Fatal("expected false for cell with empty value")
	}
}

// TestGetFormulaCellFindsFormula verifies that a sheet with mixed cells returns
// the first formula cell found.
func TestGetFormulaCellFindsFormula(t *testing.T) {
	m := newTestMachine()
	m.setCell("Sheet1", "A1", "", "plain value") // no formula
	m.setCell("Sheet1", "A2", "=EXEC(\"cmd\")", "cmd")
	c := m.getFormulaCell("Sheet1")
	if c == nil {
		t.Fatal("expected a formula cell, got nil")
	}
	if c.formula == "" {
		t.Fatal("returned cell has no formula")
	}
}

// TestGetFormulaCellAbsentSheet returns nil for an unknown sheet.
func TestGetFormulaCellAbsentSheet(t *testing.T) {
	m := newTestMachine()
	if got := m.getFormulaCell("NoSuchSheet"); got != nil {
		t.Fatalf("expected nil for absent sheet, got %+v", got)
	}
}

// TestGetFormulaCellScanCap verifies that the scan cap terminates correctly.
// A sheet with exactly maxEmulFormulaCell value-only cells (no formulas)
// must return nil — the cap is exhausted before finding any formula cell.
func TestGetFormulaCellScanCap(t *testing.T) {
	m := newTestMachine()
	for i := 0; i < maxEmulFormulaCell; i++ {
		coord := fmt.Sprintf("A%d", i+1)
		m.setCell("Sheet1", coord, "", fmt.Sprintf("v%d", i)) // no formula
	}
	// All 1000 slots scanned, none have formulas → nil.
	if got := m.getFormulaCell("Sheet1"); got != nil {
		t.Fatalf("expected nil (cap exhausted, no formula), got %+v", got)
	}
}

// TestGetFormulaCellScanCapNoPanic adds more than maxEmulFormulaCell formula
// cells; the function must not panic regardless of which cell map iteration
// returns first.
func TestGetFormulaCellScanCapNoPanic(t *testing.T) {
	m := newTestMachine()
	limit := maxEmulFormulaCell + 1
	if limit > maxEmulCells {
		limit = maxEmulCells
	}
	for i := 0; i < limit; i++ {
		coord := fmt.Sprintf("A%d", i+1)
		m.setCell("Sheet1", coord, fmt.Sprintf("=CHAR(%d)", i+65), "")
	}
	_ = m.getFormulaCell("Sheet1") // must not panic
}

// TestSetCellCapAcrossSheets verifies that maxEmulCells is enforced across
// multiple sheets, not per-sheet.
func TestSetCellCapAcrossSheets(t *testing.T) {
	m := newTestMachine()
	half := maxEmulCells / 2
	for i := 0; i < half; i++ {
		m.setCell("Sheet1", fmt.Sprintf("A%d", i+1), "", "v")
	}
	for i := 0; i < half; i++ {
		m.setCell("Sheet2", fmt.Sprintf("A%d", i+1), "", "v")
	}
	if got := m.totalCells(); got != maxEmulCells {
		t.Fatalf("after filling two sheets: totalCells = %d, want %d", got, maxEmulCells)
	}
	// One more on any sheet must be rejected.
	m.setCell("Sheet3", "A1", "", "overflow")
	if got := m.totalCells(); got != maxEmulCells {
		t.Fatalf("after overflow attempt: totalCells = %d, want %d", got, maxEmulCells)
	}
}

// TestSetCellOverwrite verifies that calling setCell twice on the same coord
// updates the cell rather than adding a duplicate.
func TestSetCellOverwrite(t *testing.T) {
	m := newTestMachine()
	m.setCell("Sheet1", "A1", "=old()", "first")
	m.setCell("Sheet1", "A1", "=new()", "second")
	if got := m.totalCells(); got != 1 {
		t.Fatalf("expected 1 cell after overwrite, got %d", got)
	}
	v, ok := m.getCellValue("Sheet1", "A1")
	if !ok || v != "second" {
		t.Fatalf("expected value %q, got %q (ok=%v)", "second", v, ok)
	}
}

// TestNewMachineFieldsNonNil checks that newMachine initialises all map fields
// so callers never dereference a nil map.
func TestNewMachineFieldsNonNil(t *testing.T) {
	m := newTestMachine()
	if m.sheets == nil {
		t.Error("sheets is nil")
	}
	if m.names == nil {
		t.Error("names is nil")
	}
	if m.visited == nil {
		t.Error("visited is nil")
	}
	if m.out == nil {
		t.Error("out is nil")
	}
	if m.totalOutput == nil {
		t.Error("totalOutput is nil")
	}
}

// TestEmulateXLMCellsZeroCellsNoPanic covers the adapter with an empty slice,
// exercising the nil-guard path in interpretXLMCells and ensuring no panic.
func TestEmulateXLMCellsZeroCellsNoPanic(t *testing.T) {
	out := make([][]byte, 0)
	total := 0
	emulateXLMCells(nil, &out, &total, time.Time{})
	emulateXLMCells([]xlmCell{}, &out, &total, time.Time{})
}
