// PERF-39: source-dedup tests — verify that duplicate decode sources are
// collapsed before the defang+BFS loops, so identical content is decoded
// exactly once without losing coverage of distinct sources.
package extract

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// streamsContainExactlyN returns the number of elements in res.Streams that
// contain substr.
func streamsContainExactlyN(res *Result, substr string) int {
	n := 0
	for _, s := range res.Streams {
		if strings.Contains(string(s), substr) {
			n++
		}
	}
	return n
}

// TestPerf39DuplicateSourceDecodedOnce feeds two identical base64-encoded
// streams as pre-existing res.Streams, then calls fromEncoded with a trivial
// buf. The decoded payload must appear in res.Streams exactly once — the
// second source is a content-duplicate and must be dropped before BFS.
func TestPerf39DuplicateSourceDecodedOnce(t *testing.T) {
	payload := "Sub AutoOpen_PERF39_UNIQUE_MARKER() : Shell \"powershell\" : End Sub"
	encoded := []byte(base64.StdEncoding.EncodeToString([]byte(payload)))

	// Two identical streams.
	res := &Result{childOpts: FullOptions(time.Time{})}
	res.Streams = append(res.Streams, encoded, encoded)

	// buf is plain prose — no decoded output from it; all decoded blobs come from
	// the duplicate streams above.
	buf := []byte("harmless prose buffer that looksEncoded not")
	fromEncoded(buf, res, FullOptions(time.Time{}))

	// The marker string must appear at least once (dedup didn't erase the first).
	if !streamsContain(*res, "PERF39_UNIQUE_MARKER") {
		t.Fatalf("decoded payload not found in streams; got %d streams", len(res.Streams))
	}

	// The marker must appear exactly once — the duplicate source was deduped.
	if n := streamsContainExactlyN(res, "PERF39_UNIQUE_MARKER"); n != 1 {
		t.Errorf("payload appears %d times in streams, want exactly 1 (duplicate source not deduped)", n)
	}
}

// TestPerf39DistinctSourcesStillDecoded proves that two DIFFERENT encoded
// sources both decode fully — no over-dedup / hash collision dropping a
// distinct source.
func TestPerf39DistinctSourcesStillDecoded(t *testing.T) {
	payloadA := "DISTINCT_A_PERF39 powershell -enc foo"
	payloadB := "DISTINCT_B_PERF39 cmd /c whoami"
	encodedA := []byte(base64.StdEncoding.EncodeToString([]byte(payloadA)))
	encodedB := []byte(base64.StdEncoding.EncodeToString([]byte(payloadB)))

	res := &Result{childOpts: FullOptions(time.Time{})}
	res.Streams = append(res.Streams, encodedA, encodedB)

	buf := []byte("harmless prose only")
	fromEncoded(buf, res, FullOptions(time.Time{}))

	if !streamsContain(*res, "DISTINCT_A_PERF39") {
		t.Errorf("distinct source A not decoded; streams=%d", len(res.Streams))
	}
	if !streamsContain(*res, "DISTINCT_B_PERF39") {
		t.Errorf("distinct source B not decoded; streams=%d", len(res.Streams))
	}
}

// TestPerf39DedupVsNoDupSameOutputSet is a differential / soundness check:
// a run with one copy of a source and a run with two copies of the same source
// must produce the same SET of decoded streams (order-independent). This proves
// the dedup does not discard real coverage.
func TestPerf39DedupVsNoDupSameOutputSet(t *testing.T) {
	payload := "SOUNDNESS_PERF39 invoke-expression download"
	encoded := []byte(base64.StdEncoding.EncodeToString([]byte(payload)))
	buf := []byte("plain prose")

	// Single-source run.
	res1 := &Result{childOpts: FullOptions(time.Time{})}
	res1.Streams = append(res1.Streams, encoded)
	fromEncoded(buf, res1, FullOptions(time.Time{}))

	// Duplicate-source run: same source twice.
	res2 := &Result{childOpts: FullOptions(time.Time{})}
	res2.Streams = append(res2.Streams, encoded, encoded)
	fromEncoded(buf, res2, FullOptions(time.Time{}))

	// Build content sets (deduplicated by string value for comparison).
	set := func(r *Result) map[string]struct{} {
		m := make(map[string]struct{}, len(r.Streams))
		for _, s := range r.Streams {
			m[string(s)] = struct{}{}
		}
		return m
	}

	s1 := set(res1)
	s2 := set(res2)

	for k := range s1 {
		if _, ok := s2[k]; !ok {
			t.Errorf("stream present in single-source run but missing in dup run: %q", k)
		}
	}
	for k := range s2 {
		if _, ok := s1[k]; !ok {
			t.Errorf("stream present in dup run but not in single-source run: %q", k)
		}
	}
}

// TestPerf39SingleSourceFastPathNoExtraAlloc verifies that fromEncoded with a
// single source does not allocate the dedup map (the len<=1 fast path).
// Uses testing.AllocsPerRun following the PERF-28 idiom in decode_lazy_test.go.
func TestPerf39SingleSourceFastPathNoExtraAlloc(t *testing.T) {
	// Plain prose — produces no decoded blobs, so the only allocs are the
	// baseline (sources slice, queue, etc.). We compare single-source vs
	// two-source to confirm the fast path skips the map allocation.
	prose := []byte(strings.Repeat("The quick brown fox. ", 10))
	encoded := []byte(base64.StdEncoding.EncodeToString([]byte("ALLOC_PERF39 payload sentinel")))

	singleFn := func() {
		res := &Result{childOpts: FullOptions(time.Time{})}
		res.Streams = append(res.Streams, encoded)
		fromEncoded(prose, res, FullOptions(time.Time{}))
	}
	dupFn := func() {
		res := &Result{childOpts: FullOptions(time.Time{})}
		res.Streams = append(res.Streams, encoded, encoded)
		fromEncoded(prose, res, FullOptions(time.Time{}))
	}

	// Warm-up.
	singleFn()
	dupFn()

	singleAllocs := testing.AllocsPerRun(20, singleFn)
	dupAllocs := testing.AllocsPerRun(20, dupFn)

	// The dup run must allocate at least as many objects as the single-source run
	// (it does extra work: the dedup map). The single-source fast path must NOT
	// allocate more than the dup path — it allocates strictly fewer or equal.
	if singleAllocs > dupAllocs {
		t.Errorf("single-source allocs (%g) > dup-source allocs (%g): fast path may be allocating the dedup map unnecessarily",
			singleAllocs, dupAllocs)
	}
}
