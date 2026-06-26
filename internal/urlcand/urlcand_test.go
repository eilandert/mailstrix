package urlcand_test

import (
	"strings"
	"testing"

	"github.com/eilandert/rspamd-yarad/internal/urlcand"
)

func TestExtractRawBeforeDeobf(t *testing.T) {
	// Buffer contains both a plain URL and a defanged one.
	data := []byte("see http://plain.example/a and hxxp://obfuscated[.]example/b")
	cands := urlcand.Extract(data, 64)
	if len(cands) < 2 {
		t.Fatalf("expected >=2 candidates, got %d: %+v", len(cands), cands)
	}
	// All raw candidates must precede all deobf candidates.
	seenDeobf := false
	for _, c := range cands {
		if c.Deobf {
			seenDeobf = true
		} else if seenDeobf {
			t.Errorf("raw candidate after deobf candidate: %+v", cands)
			break
		}
	}
	// First candidate must be the plain URL (Deobf=false).
	if cands[0].Deobf {
		t.Errorf("first candidate should be raw, got Deobf=true: %+v", cands[0])
	}
	// At least one deobf candidate.
	hasDeobf := false
	for _, c := range cands {
		if c.Deobf {
			hasDeobf = true
			break
		}
	}
	if !hasDeobf {
		t.Error("expected at least one deobf candidate")
	}
}

func TestExtractBudgetBoundsTotal(t *testing.T) {
	// Build a buffer with more URLs than the budget allows.
	var sb strings.Builder
	for i := 0; i < 10; i++ {
		sb.WriteString("http://host.example/path ")
	}
	// Add a defanged URL too.
	sb.WriteString("hxxp://obf[.]example/x ")
	data := []byte(sb.String())

	budget := 5
	cands := urlcand.Extract(data, budget)
	if len(cands) > budget {
		t.Errorf("got %d candidates with budget %d", len(cands), budget)
	}
}

func TestExtractNoDefangGate(t *testing.T) {
	// Buffer contains no defang trigger bytes ([, (, {, x, X) — only plain URLs.
	data := []byte("see http://plain.host/path and https://other.host/page")
	cands := urlcand.Extract(data, 64)
	for _, c := range cands {
		if c.Deobf {
			t.Errorf("got Deobf candidate from buffer with no defang triggers: %+v", c)
		}
	}
}

func TestExtractEmptyBuffer(t *testing.T) {
	if cands := urlcand.Extract([]byte{}, 64); cands != nil {
		t.Errorf("empty buffer should return nil, got %+v", cands)
	}
	if cands := urlcand.Extract(nil, 64); cands != nil {
		t.Errorf("nil buffer should return nil, got %+v", cands)
	}
}

func TestExtractNoURLs(t *testing.T) {
	if cands := urlcand.Extract([]byte("no urls here just text"), 64); cands != nil {
		t.Errorf("no-URL buffer should return nil, got %+v", cands)
	}
}

func TestExtractOrdering(t *testing.T) {
	// Multiple raw URLs + multiple defanged URLs: ordering must be raw-all then deobf-all.
	data := []byte("http://a.example/1 https://b.example/2 hxxp://c[.]example/3 hxxp://d[.]example/4")
	cands := urlcand.Extract(data, 64)

	rawCount := 0
	deobfCount := 0
	for _, c := range cands {
		if !c.Deobf {
			rawCount++
		}
	}
	for _, c := range cands {
		if c.Deobf {
			deobfCount++
		}
	}
	if rawCount < 2 {
		t.Errorf("expected >=2 raw candidates, got %d", rawCount)
	}
	if deobfCount < 2 {
		t.Errorf("expected >=2 deobf candidates, got %d", deobfCount)
	}

	// Verify ordering: all raw before any deobf.
	inDeobf := false
	for _, c := range cands {
		if c.Deobf {
			inDeobf = true
		} else if inDeobf {
			t.Errorf("raw candidate appeared after deobf section: %+v", cands)
			break
		}
	}
}

func TestExtractDefaultBudget(t *testing.T) {
	// maxURLs=0 should default to 64.
	data := []byte("http://a.example/x")
	cands := urlcand.Extract(data, 0)
	if len(cands) == 0 {
		t.Error("zero maxURLs should default to 64, not drop all candidates")
	}
}
