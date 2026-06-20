package extract

// Document-properties string extraction.
//
// Attackers hide C2 URLs, commands, and payload strings in document properties
// that VBA-only scanners never see:
//
//   - OOXML: docProps/core.xml, docProps/app.xml, docProps/custom.xml
//     (OPC core/application/custom properties), customXml/item*.xml (custom XML
//     parts), and word/settings.xml docVars (w:docVar elements whose w:val holds
//     attacker-controlled strings).
//
//   - OLE2: \x05SummaryInformation and \x05DocumentSummaryInformation streams
//     (binary property set streams, MS-OLEPS). The spec format is complex; we
//     just carve printable ASCII runs >= minPrintRun bytes, same approach as
//     userform.go -- sufficient for URL/command detection.
//
// Each non-empty string >= 8 bytes is emitted as a separate stream, preceded by
// a synthetic "DOCPROPS-STRINGS" marker so YARA rules can anchor on it.
// Fail-open: any parse error is silently ignored. Respects deadline and the
// shared maxStreams cap.

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// docpropsCap is the per-file read limit for OOXML property XML parts (zip-bomb
// guard; property files are tiny in practice, rarely > a few KiB).
const docpropsCap = 512 << 10 // 512 KiB

// maxDocPropsStreams caps how many carved strings we emit per document from
// document properties. Guards a crafted file that stuffs megabytes of text into
// custom properties.
const maxDocPropsStreams = 128

// ooxmlPropParts lists the OOXML zip entry names that carry document-property
// strings (OPC core/application properties and custom XML parts).
var ooxmlPropParts = []string{
	"docProps/core.xml",
	"docProps/app.xml",
	"docProps/custom.xml",
}

// fromOOXMLDocProps scans the already-opened OOXML zip for document-property
// parts (docProps/core.xml, docProps/app.xml, docProps/custom.xml,
// customXml/item*.xml) and word/settings.xml (docVars). For each XML file it
// walks the token stream and collects all CharData text nodes. For
// word/settings.xml it additionally extracts w:docVar/@w:val attribute values.
// Each collected string >= minPrintRun bytes is emitted as a separate stream,
// preceded by a "DOCPROPS-STRINGS" marker.
// Fail-open; respects deadline and maxStreams / maxDocPropsStreams caps.
// Uses the same *[][]byte convention as the other fromOOXML* helpers so it
// slots into the fromOOXML local-out accumulator without an extra allocation.
func fromOOXMLDocProps(zr *zip.Reader, out *[][]byte, deadline time.Time) {
	if expired(deadline) {
		return
	}

	var carved [][]byte

	// add appends s (trimmed) to carved if it meets the length threshold and caps.
	// Returns false when the cap is hit (caller should stop iterating).
	add := func(s string) bool {
		s = strings.TrimSpace(s)
		if len(s) < minPrintRun {
			return true
		}
		if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
			return false
		}
		carved = append(carved, []byte(s))
		return true
	}

	// Build a name-to-entry index for O(1) lookup.
	idx := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		idx[f.Name] = f
	}

	// extractXMLText walks an XML token stream and calls add for each CharData node.
	extractXMLText := func(raw []byte) {
		dec := xml.NewDecoder(bytes.NewReader(raw))
		dec.Strict = false
		for {
			if expired(deadline) {
				break
			}
			if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
				break
			}
			tok, err := dec.Token()
			if err != nil {
				break // EOF or malformed -- fail-open
			}
			if cd, ok := tok.(xml.CharData); ok {
				if !add(string(cd)) {
					break
				}
			}
		}
	}

	// readEntry reads a zip entry up to docpropsCap bytes; returns nil on error or
	// if the entry's uncompressed size exceeds the cap.
	readEntry := func(f *zip.File) []byte {
		if f.UncompressedSize64 > docpropsCap {
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(rc, docpropsCap))
		rc.Close() // #nosec G104 -- zip entry close; error is unrecoverable here
		if err != nil || len(raw) == 0 {
			return nil
		}
		return raw
	}

	// 1. Fixed property parts.
	for _, name := range ooxmlPropParts {
		if expired(deadline) {
			break
		}
		if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
			break
		}
		f, ok := idx[name]
		if !ok {
			continue
		}
		raw := readEntry(f)
		if raw == nil {
			continue
		}
		extractXMLText(raw)
	}

	// 2. customXml/item*.xml parts (dynamic names -- must walk the zip directory).
	for _, f := range zr.File {
		if expired(deadline) {
			break
		}
		if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
			break
		}
		name := f.Name
		if !strings.HasPrefix(name, "customXml/item") || !strings.HasSuffix(name, ".xml") {
			continue
		}
		raw := readEntry(f)
		if raw == nil {
			continue
		}
		extractXMLText(raw)
	}

	// 3. word/settings.xml -- docVar attribute values + general text nodes.
	if f, ok := idx["word/settings.xml"]; ok && !expired(deadline) {
		raw := readEntry(f)
		if raw != nil {
			// First pass: extract w:docVar/@w:val attribute values.
			dec := xml.NewDecoder(bytes.NewReader(raw))
			dec.Strict = false
		docVarLoop:
			for {
				if expired(deadline) {
					break
				}
				if len(carved) >= maxDocPropsStreams || len(*out)+len(carved) >= maxStreams {
					break
				}
				tok, err := dec.Token()
				if err != nil {
					break
				}
				se, ok := tok.(xml.StartElement)
				if !ok || se.Name.Local != "docVar" {
					continue
				}
				for _, attr := range se.Attr {
					if attr.Name.Local == "val" {
						if !add(attr.Value) {
							break docVarLoop
						}
					}
				}
			}
			// Second pass: general text nodes.
			extractXMLText(raw)
		}
	}

	if len(carved) == 0 {
		return
	}

	// Emit marker first so YARA rules can anchor on it.
	if len(*out) >= maxStreams {
		return
	}
	*out = append(*out, []byte(docPropsMarker))
	for _, s := range carved {
		if len(*out) >= maxStreams {
			break
		}
		*out = append(*out, s)
	}
}

// oleDocPropsStreamNames lists the OLE2 stream names that carry binary
// property-set data (MS-OLEPS SummaryInformation / DocumentSummaryInformation).
var oleDocPropsStreamNames = []string{
	"\x05SummaryInformation",
	"\x05DocumentSummaryInformation",
}

// fromOLEDocProps looks for SummaryInformation and DocumentSummaryInformation
// streams in the already-parsed OLE2 file and carves printable ASCII runs
// >= minPrintRun bytes from their raw bytes. We use the same carveStrings
// approach as userform.go -- the full MS-OLEPS property-set parse is
// unnecessary for payload detection. Emits a "DOCPROPS-STRINGS" marker
// followed by each carved string.
// Fail-open; respects deadline and maxStreams / maxDocPropsStreams.
func fromOLEDocProps(ole *oleparse.OLEFile, res *Result, deadline time.Time) {
	if expired(deadline) {
		return
	}
	if ole == nil || len(ole.Directory) == 0 {
		return
	}

	var carved [][]byte

	for _, name := range oleDocPropsStreamNames {
		if expired(deadline) {
			break
		}
		s := ole.FindStreamByName(name)
		if s == nil {
			continue
		}
		data := ole.GetStream(s.Index)
		if len(data) == 0 {
			continue
		}
		for _, run := range carveStrings(data) {
			if len(carved) >= maxDocPropsStreams || len(res.Streams)+len(carved) >= maxStreams {
				break
			}
			carved = append(carved, run)
		}
	}

	if len(carved) == 0 {
		return
	}

	// Emit marker first.
	res.HasDocProps = true
	res.Streams = append(res.Streams, []byte(docPropsMarker))
	for _, s := range carved {
		if len(res.Streams) >= maxStreams {
			break
		}
		res.Streams = append(res.Streams, s)
	}
}

// docPropsMarker is the synthetic marker emitted as the first stream when
// document-property strings are found. Used in tests.
const docPropsMarker = "DOCPROPS-STRINGS"

// hasDocPropsMarker reports whether any stream in streams is the docprops marker.
func hasDocPropsMarker(streams [][]byte) bool {
	for _, s := range streams {
		if bytes.Equal(s, []byte(docPropsMarker)) {
			return true
		}
	}
	return false
}
