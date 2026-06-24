package extract

import (
	"testing"
	"time"
)

// A valid PE that exports xlAutoOpen must be flagged XLL-ADDIN.
func TestXLLFlagged(t *testing.T) {
	buf := append(minimalPE(), []byte("....xlAutoOpen\x00xlAddInManagerInfo\x00....")...)
	res := Extract(buf, time.Time{})
	if !res.IsXLL {
		t.Error("XLL PE not flagged")
	}
	if !streamsContain(res, "XLL-ADDIN") {
		t.Error("XLL PE did not emit XLL-ADDIN marker")
	}
}

// A valid PE that does NOT export the XLL contract must NOT be flagged (an
// ordinary DLL/exe is not an add-in).
func TestXLLPlainPENotFlagged(t *testing.T) {
	buf := append(minimalPE(), []byte("....DllMain\x00SomeOtherExport\x00....")...)
	res := Extract(buf, time.Time{})
	if res.IsXLL {
		t.Error("non-XLL PE falsely flagged")
	}
	if streamsContain(res, "XLL-ADDIN") {
		t.Error("non-XLL PE falsely emitted XLL-ADDIN marker")
	}
}

// Non-PE content that merely contains the string "xlAutoOpen" (e.g. text, source
// code, docs) must NOT be flagged — the valid-PE gate is required.
func TestXLLNonPEStringNotFlagged(t *testing.T) {
	buf := []byte("This document describes the xlAutoOpen callback in the Excel SDK. " +
		"Call xlAutoOpen when the add-in loads. xlAddInManagerInfo too.")
	res := Extract(buf, time.Time{})
	if res.IsXLL {
		t.Error("plain text mentioning xlAutoOpen falsely flagged XLL")
	}
}

// A bare PE with no exports section content at all must NOT be flagged.
func TestXLLBarePENotFlagged(t *testing.T) {
	res := Extract(minimalPE(), time.Time{})
	if res.IsXLL {
		t.Error("bare PE falsely flagged XLL")
	}
}
