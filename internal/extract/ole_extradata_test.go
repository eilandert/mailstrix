package extract

import (
	"bytes"
	"testing"
	"time"
)

// fromOLEExtraData flags a non-zero payload stapled past the last FAT-allocated
// sector of a CFB compound file (oletools "extra data after last sector"). These
// tests build a valid CFB via buildMinimalMSI, then append/withhold trailing data.

func streamsHave(res Result, needle []byte) bool {
	for _, s := range res.Streams {
		if bytes.Contains(s, needle) {
			return true
		}
	}
	return false
}

func TestOLEExtraData_AppendedPayloadFlaggedAndCarved(t *testing.T) {
	base := buildMinimalMSI(t, []byte("benign workbook"))
	payload := bytes.Repeat([]byte("EXTRA-PAYLOAD-MZ\x90"), 64) // ~1KB, non-zero, > extraDataMinBytes
	buf := append(append([]byte(nil), base...), payload...)

	res := Extract(buf, time.Time{})

	if !streamsHave(res, []byte("OLE2-EXTRA-DATA")) {
		t.Error("appended-data CFB did not emit OLE2-EXTRA-DATA marker")
	}
	if !streamsHave(res, []byte("EXTRA-PAYLOAD-MZ")) {
		t.Error("appended payload was not carved into res.Streams for scanning")
	}
}

func TestOLEExtraData_CleanCFBNotFlagged(t *testing.T) {
	// A well-formed CFB with no trailing bytes must NOT trip the marker.
	buf := buildMinimalMSI(t, []byte("benign workbook"))
	res := Extract(buf, time.Time{})
	if streamsHave(res, []byte("OLE2-EXTRA-DATA")) {
		t.Error("clean CFB falsely flagged OLE2-EXTRA-DATA")
	}
}

func TestOLEExtraData_ZeroPaddingNotFlagged(t *testing.T) {
	// Trailing all-zero bytes are free-sector padding, not an appended payload.
	base := buildMinimalMSI(t, []byte("benign workbook"))
	buf := append(append([]byte(nil), base...), make([]byte, 2048)...)
	res := Extract(buf, time.Time{})
	if streamsHave(res, []byte("OLE2-EXTRA-DATA")) {
		t.Error("all-zero tail padding falsely flagged OLE2-EXTRA-DATA")
	}
}

func TestOLEExtraData_SubThresholdNotFlagged(t *testing.T) {
	// A trailing blob below extraDataMinBytes is ignored as sub-sector noise.
	base := buildMinimalMSI(t, []byte("benign workbook"))
	buf := append(append([]byte(nil), base...), bytes.Repeat([]byte("x"), 16)...)
	res := Extract(buf, time.Time{})
	if streamsHave(res, []byte("OLE2-EXTRA-DATA")) {
		t.Error("sub-threshold trailing blob falsely flagged OLE2-EXTRA-DATA")
	}
}
