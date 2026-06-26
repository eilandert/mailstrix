package extract

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

// b64StuffedDoc embeds base64(pad || payload) inside a plain-text body, the shape
// a dropper uses to smuggle a PE into an OOXML docProps field. The leading pad
// pushes the payload's first byte to a non-zero offset of the decoded blob.
func b64StuffedDoc(pad, payload []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(append(append([]byte{}, pad...), payload...))
	return []byte("benign cover text\n<dc:description>" + enc + "</dc:description>\nmore text\n")
}

// A pad-prefixed PE base64-stuffed into a text body must be carved MZ-aligned and
// flagged BASE64-PE-CARVE — the case YARA's pe module (MZ@0 anchor) otherwise
// misses on the raw decoded blob.
func TestCarveBase64StuffedPE(t *testing.T) {
	pe := minimalPE()
	doc := b64StuffedDoc(bytes.Repeat([]byte{'A'}, 30), pe)
	res := Extract(doc, time.Time{})
	if !streamsContain(res, "BASE64-PE-CARVE") {
		t.Fatal("pad-prefixed base64 PE did not emit BASE64-PE-CARVE marker")
	}
	// An MZ-aligned copy of the PE must be present as a stream (offset 0 == MZ).
	found := false
	for _, s := range res.Streams {
		if bytes.HasPrefix(s, mzMagic) && isValidPEAt(s, 0) {
			found = true
			break
		}
	}
	if !found {
		t.Error("no MZ-aligned PE stream was carved")
	}
}

// A base64 blob that decodes to non-PE content must NOT carve or flag — the carve
// validates through e_lfanew, so a benign payload yields nothing.
func TestCarveBenignBase64NoFlag(t *testing.T) {
	doc := b64StuffedDoc(bytes.Repeat([]byte{'A'}, 30), []byte("just some harmless decoded text, definitely not an executable image"))
	res := Extract(doc, time.Time{})
	if streamsContain(res, "BASE64-PE-CARVE") {
		t.Error("benign base64 payload falsely flagged BASE64-PE-CARVE")
	}
}

// A PE that decodes already MZ-aligned at offset 0 must NOT trip the carve (the pe
// module already sees the header; carving would be a redundant duplicate stream).
func TestCarveAlignedPENoFlag(t *testing.T) {
	doc := b64StuffedDoc(nil, minimalPE()) // no pad -> MZ at offset 0 of the decoded blob
	res := Extract(doc, time.Time{})
	if streamsContain(res, "BASE64-PE-CARVE") {
		t.Error("already-MZ-aligned decoded PE falsely emitted BASE64-PE-CARVE")
	}
}

// carveEmbeddedPEs unit: a decode-pass stream with a pad-prefixed PE yields an
// aligned child + one marker; the bound on carved children is honoured.
func TestCarveEmbeddedPEsUnit(t *testing.T) {
	pe := minimalPE()
	blob := append(bytes.Repeat([]byte{0x00}, 17), pe...)
	res := Result{Streams: [][]byte{blob}}
	carveEmbeddedPEs(&res, 0)
	if !streamsContain(res, "BASE64-PE-CARVE") {
		t.Fatal("carveEmbeddedPEs did not emit marker")
	}
	// Stream 1 is the aligned carve; stream 2 the marker.
	if len(res.Streams) != 3 || !isValidPEAt(res.Streams[1], 0) {
		t.Errorf("expected [blob, aligned-PE, marker]; got %d streams", len(res.Streams))
	}
}
