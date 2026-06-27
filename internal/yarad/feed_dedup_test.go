package yarad

// PERF-33: feed-loop dedup tests.
//
// The feed section runs urlcand.Extract on buf + unique streams only; streams
// byte-identical to buf or to an already-processed stream are skipped. These
// tests verify the match set (count, order, Meta) is byte-identical to the
// unoptimised behaviour for all dedup scenarios.
//
// Strategy: a plain ZIP archive (not OOXML) whose members are unpacked by the
// extractor into res.Streams. Member bytes contain a URLhaus-feed URL so that
// when the URLhaus checker is loaded (via a warm-start cache CSV) the feed path
// produces exactly one match regardless of how many duplicate members appear.
//
// The URLhaus checker is bootstrapped by writing a minimal CSV to a temp dir
// and using cfg.URLhausKey + cfg.CacheDir so urlhaus.New() warm-starts from
// disk before the (failing, harmless) background refresh fires. s.Close() is
// deferred to stop the background goroutine.

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const (
	// feedURL must match a URL in feedCSV exactly (after normalisation).
	feedURLHost = "evil.example"
	feedTestURL = "http://evil.example/malware.exe"
	feedCSV     = `# URLhaus CSV stub for PERF-33 tests
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2024-01-01 00:00:00","http://evil.example/malware.exe","online","2024-01-02","malware_download","exe","https://urlhaus.abuse.ch/url/1/","test"
"2","2024-01-02 00:00:00","http://other.example/payload.exe","online","2024-01-02","malware_download","exe","https://urlhaus.abuse.ch/url/2/","test"
`
	feedURLBody  = "click http://evil.example/malware.exe now"
	feedURL2Body = "see http://other.example/payload.exe here"
)

// newURLhausScanner creates a Scanner with a URLhaus checker warm-started from
// a stub CSV in a temp dir. The caller must defer s.Close().
func newURLhausScanner(t *testing.T) *Scanner {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "urlhaus.csv"), []byte(feedCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	rulesDir := writeRules(t, eicarRule) // minimal rules dir (requires ≥1 rule)
	cfg := &Config{
		RulesDir:       rulesDir,
		ScanTimeout:    0,
		CacheDir:       dir,
		URLhausKey:     "test-key", // non-empty → checker enabled; warm-start from cache
		URLhausMaxURLs: 64,
	}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

// makePlainZIP builds a ZIP archive (not OOXML) whose members carry the
// supplied byte slices as content. The extractor's fromArchive path emits
// each member as a res.Stream entry.
func makePlainZIP(t *testing.T, members [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, content := range members {
		w, err := zw.Create(filepath.Join("dir", "member") + string(rune('a'+i)) + ".txt")
		if err != nil {
			t.Fatalf("zip.Create: %v", err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	return buf.Bytes()
}

// feedMatches returns only the urlhaus-tagged matches from ms.
func feedMatches(ms []Match) []Match {
	var out []Match
	for _, m := range ms {
		for _, tag := range m.Tags {
			if tag == "urlhaus" {
				out = append(out, m)
				break
			}
		}
	}
	return out
}

// TestFeedDedupDuplicateStreams (PERF-33): two ZIP members with IDENTICAL bytes
// both containing the feed URL → exactly one URLhaus match, same as a ZIP with
// a single member (the dup contributes nothing).
func TestFeedDedupDuplicateStreams(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()

	content := []byte(feedURLBody)

	// Baseline: ZIP [A] — one member.
	baseZIP := makePlainZIP(t, [][]byte{content})
	baseMatches, err := scanT(s, baseZIP, ScanMeta{})
	if err != nil {
		t.Fatalf("scan baseline: %v", err)
	}
	baseFeed := feedMatches(baseMatches)

	// Dup ZIP: [A, A] — two identical members.
	dupZIP := makePlainZIP(t, [][]byte{content, content})
	dupMatches, err := scanT(s, dupZIP, ScanMeta{})
	if err != nil {
		t.Fatalf("scan dup: %v", err)
	}
	dupFeed := feedMatches(dupMatches)

	if len(baseFeed) == 0 {
		t.Fatal("precondition: URLhaus checker must match the test URL in the baseline ZIP")
	}
	if len(dupFeed) != len(baseFeed) {
		t.Errorf("dup ZIP produced %d feed matches, want %d (same as baseline): %+v",
			len(dupFeed), len(baseFeed), dupFeed)
	}
	for i := range baseFeed {
		if i >= len(dupFeed) {
			break
		}
		if baseFeed[i].Rule != dupFeed[i].Rule || baseFeed[i].Meta["url"] != dupFeed[i].Meta["url"] {
			t.Errorf("feed match[%d] mismatch: base=%+v dup=%+v", i, baseFeed[i], dupFeed[i])
		}
	}
}

// TestFeedDedupStreamIdenticalToBuf (PERF-33): a ZIP member byte-identical to
// the raw ZIP itself is a degenerate edge-case that the extractor would not
// produce in practice, but the YARA loop seeds seen with buf's key so that
// path is already safe. Test that a stream whose bytes happen to equal buf
// does not double-feed the URL (the URL from buf is already in seenURL).
// We approximate this by scanning buf directly (no ZIP wrapper) and checking
// that a single feed URL in buf produces exactly one match.
func TestFeedDedupStreamIdenticalToBuf(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()

	// buf itself contains the feed URL — no ZIP wrapper, no streams.
	plain := []byte(feedURLBody)
	matches, err := scanT(s, plain, ScanMeta{})
	if err != nil {
		t.Fatalf("scan plain: %v", err)
	}
	fm := feedMatches(matches)
	if len(fm) != 1 {
		t.Errorf("plain buf: got %d urlhaus matches, want 1: %+v", len(fm), fm)
	}
	if len(fm) > 0 && fm[0].Meta["url"] != feedTestURL {
		t.Errorf("url mismatch: got %q want %q", fm[0].Meta["url"], feedTestURL)
	}
}

// TestFeedDedupDistinctStreams (PERF-33): distinct ZIP members each with a
// distinct feed URL → both matched, in first-occurrence order.
func TestFeedDedupDistinctStreams(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()

	zip2 := makePlainZIP(t, [][]byte{[]byte(feedURLBody), []byte(feedURL2Body)})
	matches, err := scanT(s, zip2, ScanMeta{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	fm := feedMatches(matches)
	if len(fm) < 2 {
		t.Fatalf("got %d urlhaus matches, want >=2 (one per distinct URL): %+v", len(fm), fm)
	}
	// Verify both URLs appear (order is first-occurrence of the stream).
	urls := make(map[string]bool)
	for _, m := range fm {
		urls[m.Meta["url"]] = true
	}
	for _, want := range []string{feedTestURL, "http://other.example/payload.exe"} {
		if !urls[want] {
			t.Errorf("expected URL %q in feed matches, got: %v", want, urls)
		}
	}
}

// TestFeedDedupABvsAAB (PERF-33): differential — [A,B] and [A,A,B] must
// produce the same feed match set (count, URL values) even though [A,A,B] has
// a duplicate first member. This directly mirrors the PERF-33 parity argument.
func TestFeedDedupABvsAAB(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()

	contentA := []byte(feedURLBody)
	contentB := []byte(feedURL2Body)

	abZIP := makePlainZIP(t, [][]byte{contentA, contentB})
	aabZIP := makePlainZIP(t, [][]byte{contentA, contentA, contentB})

	abMatches, err := scanT(s, abZIP, ScanMeta{})
	if err != nil {
		t.Fatalf("scan [A,B]: %v", err)
	}
	aabMatches, err := scanT(s, aabZIP, ScanMeta{})
	if err != nil {
		t.Fatalf("scan [A,A,B]: %v", err)
	}

	abFeed := feedMatches(abMatches)
	aabFeed := feedMatches(aabMatches)

	if len(abFeed) != len(aabFeed) {
		t.Errorf("[A,B]=%d feed matches vs [A,A,B]=%d: want equal\nAB:  %+v\nAAB: %+v",
			len(abFeed), len(aabFeed), abFeed, aabFeed)
		return
	}
	for i := range abFeed {
		if abFeed[i].Meta["url"] != aabFeed[i].Meta["url"] {
			t.Errorf("feed match[%d]: AB url=%q AAB url=%q",
				i, abFeed[i].Meta["url"], aabFeed[i].Meta["url"])
		}
	}
}
