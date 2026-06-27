package urlcand_test

// Tests for PERF-29: no-candidate prefilter in urlcand.Extract.
// These tests verify:
//   1. Differential: Extract output is identical before/after the prefilter
//      for all interesting input classes.
//   2. Soundness: every input that DOES yield candidates passes the prefilter
//      (no false-negative gate).
//   3. Clean buffers return nil without allocating the defanged string.

import (
	"strings"
	"testing"

	"github.com/eilandert/rspamd-yarad/internal/urlcand"
)

// ---------------------------------------------------------------------------
// 1. Differential: prefilter must not change Extract output for any input
// ---------------------------------------------------------------------------

// TestPrefilterDifferential verifies that a table of inputs produces identical
// candidate sets. Because the prefilter is internal to Extract, we simply run
// Extract twice on each input and assert determinism, then verify the output
// matches the expected shape.
func TestPrefilterDifferential(t *testing.T) {
	cases := []struct {
		name      string
		input     []byte
		wantAny   bool   // true = expect at least one candidate
		wantDeobf bool   // true = expect at least one Deobf=true candidate
		wantNone  bool   // true = expect nil / empty result
		contains  string // if wantAny, the Raw field of some candidate must contain this
	}{
		{
			name:     "clean prose — no URL",
			input:    []byte("Hello, this is a normal email with no links at all."),
			wantNone: true,
		},
		{
			name:     "clean prose with word 'http' but no scheme separator",
			input:    []byte("The http protocol spec is defined in RFC 7230. No actual link here."),
			wantNone: true,
		},
		{
			name:    "plain http URL",
			input:   []byte("visit http://example.com/path for details"),
			wantAny: true, contains: "http://example.com",
		},
		{
			name:    "plain https URL",
			input:   []byte("download from https://cdn.example.com/file.exe now"),
			wantAny: true, contains: "https://cdn.example.com",
		},
		{
			name:    "uppercase HTTP URL (case-insensitive regexp)",
			input:   []byte("see HTTP://EXAMPLE.COM/PATH"),
			wantAny: true, contains: "HTTP://EXAMPLE.COM",
		},
		{
			name:     "binary-like buffer with no URL bytes",
			input:    []byte{0x00, 0x01, 0xD0, 0xCF, 0x11, 0xE0, 0xFF, 0xFE, 0x41, 0x42},
			wantNone: true,
		},
		{
			name:    "defanged hxxp URL",
			input:   []byte("click hxxp://evil[.]example[.]com/malware.exe"),
			wantAny: true, wantDeobf: true, contains: "http://evil.example.com",
		},
		{
			name:    "defanged hXXp URL",
			input:   []byte("download hXXp://bad[.]actor/payload"),
			wantAny: true, wantDeobf: true, contains: "http://bad.actor",
		},
		{
			name:    "defanged hxxps URL",
			input:   []byte("connect to hxxps://malicious[.]example/stage2"),
			wantAny: true, wantDeobf: true, contains: "https://malicious.example",
		},
		{
			name:    "defanged [.] dot only",
			input:   []byte("http://normal.host[.]com/path"),
			wantAny: true, wantDeobf: true, contains: "http://normal.host",
		},
		{
			name:    "defanged (.) dot",
			input:   []byte("http://obfuscated(.)domain/path"),
			wantAny: true, wantDeobf: true,
		},
		{
			name:    "defanged [://] form",
			input:   []byte("hxxp[://]evil.example.com/payload"),
			wantAny: true, wantDeobf: true, contains: "http://evil.example.com",
		},
		{
			name:    "defanged http[:]// form",
			input:   []byte("http[:]//another.host/page"),
			wantAny: true, wantDeobf: true, contains: "http://another.host",
		},
		{
			name:    "URL split context — URL present but mixed with prose",
			input:   []byte("The malware downloads from https://c2.example.net/stage and runs it."),
			wantAny: true, contains: "https://c2.example.net",
		},
		{
			name:     "adversarial near-miss: 'http' word, no ://",
			input:    []byte("This uses http as a transport but there is no URL separator here."),
			wantNone: true,
		},
		{
			name:     "empty buffer",
			input:    nil,
			wantNone: true,
		},
		{
			name:     "buffer with '[' but no URL prefix",
			input:    []byte("some [text] in [brackets] but no URL scheme"),
			wantNone: true,
		},
		{
			name:     "buffer with 'x' but no URL",
			input:    []byte("fox box wax hex maximum next extra"),
			wantNone: true,
		},
	}

	for _, c := range cases {
		cands := urlcand.Extract(c.input, 64)

		// Determinism: second call must return the same result.
		cands2 := urlcand.Extract(c.input, 64)
		if len(cands) != len(cands2) {
			t.Errorf("[%s] non-deterministic: run1 %d cands, run2 %d cands", c.name, len(cands), len(cands2))
		}

		if c.wantNone {
			if len(cands) != 0 {
				t.Errorf("[%s] expected nil/empty, got %d candidates: %+v", c.name, len(cands), cands)
			}
			continue
		}

		if c.wantAny && len(cands) == 0 {
			t.Errorf("[%s] expected >=1 candidate, got none", c.name)
			continue
		}

		if c.contains != "" {
			found := false
			for _, cand := range cands {
				if strings.Contains(cand.Raw, c.contains) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("[%s] no candidate contains %q; got %+v", c.name, c.contains, cands)
			}
		}

		if c.wantDeobf {
			hasDeobf := false
			for _, cand := range cands {
				if cand.Deobf {
					hasDeobf = true
					break
				}
			}
			if !hasDeobf {
				t.Errorf("[%s] expected Deobf=true candidate, got none: %+v", c.name, cands)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Soundness: for every input that produces candidates, the prefilter passes
// ---------------------------------------------------------------------------

// TestPrefilterSoundness verifies that the prefilter (hasCandidateURL) never
// produces a false negative: for every input from which Extract returns at
// least one candidate, the prefilter must have allowed it through.
//
// We test this behaviourally: if the prefilter were to gate out a real
// candidate, Extract would return nil for that input. So we assert that for
// a corpus of inputs known to yield candidates, Extract returns non-nil.
func TestPrefilterSoundness(t *testing.T) {
	corpus := []struct {
		name  string
		input []byte
	}{
		{"http plain", []byte("http://example.com/path")},
		{"https plain", []byte("https://example.com/path")},
		{"HTTP uppercase", []byte("HTTP://EXAMPLE.COM/PATH")},
		{"HTTPS uppercase", []byte("HTTPS://EXAMPLE.COM/PATH")},
		{"hxxp defanged", []byte("hxxp://evil.example.com/x")},
		{"hXXp defanged", []byte("hXXp://evil.example.com/x")},
		{"hxxps defanged", []byte("hxxps://evil.example.com/x")},
		{"hXXps defanged", []byte("hXXps://evil.example.com/x")},
		{"[.] defanged dot", []byte("http://host[.]example/path")},
		{"(.) defanged dot", []byte("http://host(.)example/path")},
		{"{.} defanged dot", []byte("http://host{.}example/path")},
		{"[://] defanged scheme", []byte("hxxp[://]evil.example.com/x")},
		{"http[:]// defanged colon", []byte("http[:]//evil.example.com/x")},
		{"[dot] defanged", []byte("http://host[dot]example/path")},
		{"(dot) defanged", []byte("http://host(dot)example/path")},
		{"url in prose", []byte("please download from https://cdn.example.org/file.exe and run")},
		{"multiple URLs", []byte("http://a.example/ http://b.example/ http://c.example/")},
		{"mixed raw and defanged", []byte("http://raw.example/ and hxxp://defanged[.]example/")},
	}

	for _, c := range corpus {
		cands := urlcand.Extract(c.input, 64)
		if len(cands) == 0 {
			t.Errorf("[%s] prefilter false-negative: Extract returned nil for a known-candidate input",
				c.name)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. Clean buffers: no allocation on the fast path
// ---------------------------------------------------------------------------

// TestPrefilterCleanBufferNoAlloc verifies that a clean prose buffer (no "://"
// and no defang trigger bytes) causes Extract to return early without allocating
// the defanged string. We use testing.AllocsPerRun to confirm the clean path
// allocates fewer objects than the URL path.
func TestPrefilterCleanAllocsLessThanURLPath(t *testing.T) {
	cleanBuf := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 20))
	urlBuf := []byte("http://malware.example.com/dropper.exe")

	// Warm up.
	urlcand.Extract(cleanBuf, 64)
	urlcand.Extract(urlBuf, 64)

	cleanAllocs := testing.AllocsPerRun(50, func() {
		urlcand.Extract(cleanBuf, 64)
	})
	urlAllocs := testing.AllocsPerRun(50, func() {
		urlcand.Extract(urlBuf, 64)
	})

	// The clean path must allocate fewer objects than the URL path.
	// Before PERF-29 the clean path always ran the regexp (which allocates
	// [][]byte for matches even if empty). After PERF-29 it returns nil before
	// the regexp fires.
	if cleanAllocs >= urlAllocs {
		t.Errorf("clean path allocs (%g) >= URL path allocs (%g): prefilter may not be skipping the regexp",
			cleanAllocs, urlAllocs)
	}
}

// TestPrefilterCleanAllocsZero asserts that a clean prose buffer causes zero
// heap allocations in Extract. The prefilter uses bytes.Contains and
// bytes.ContainsAny — both allocation-free — and returns nil on mismatch.
func TestPrefilterCleanAllocsZero(t *testing.T) {
	cleanBuf := []byte(strings.Repeat("plain prose no links here at all. ", 30))

	allocs := testing.AllocsPerRun(50, func() {
		urlcand.Extract(cleanBuf, 64)
	})
	if allocs > 0 {
		t.Errorf("clean prose buffer: expected 0 allocs, got %g", allocs)
	}
}
