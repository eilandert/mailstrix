package extract

import (
	"bytes"
	"os"
	"testing"
)

// powershell_asmload.yara ships PS1_Despaced_Assembly_Load_Loader, closing six
// live 0-hit corpus misses (07fec91f, 44d1e04d, 76c69bf4, ac8de596, dd3df5ff,
// f70a8b4c): UTF-16LE Brazilian .NET loader stubs that de-space URLs via
// .Replace(' ',''), carry a %base64% sentinel, reconstruct a .NET DLL from a
// local text file via Get-Content/-split/[byte], then load it in-memory via
// Assembly::Load.
//
// yarad's unit suite does not link libyara, so -- like js_obfuscation and
// powershell_cff -- this asserts the rule SOURCE is present and well-formed.
// The actual compile+match runs in the Docker `full` CI stage (compile-rules.sh
// runs yarac over every local rule, then the runtime scanner job scans fixtures).
//
// Guards catch the two classes of silent failure seen in past rules:
//   - YARA backreferences (\1..\9): yarac rejects them; compile-rules.sh then
//     silently skips the rule, shipping nothing (GOTCHA-1, #172).
//   - Missing `ascii wide`: samples are UTF-16LE; without `wide` the strings
//     never match (GOTCHA-2, #172).
//   - Nested unbounded quantifiers ){N,}: catastrophic-backtracking risk (#174/#177).

func loadPS1AsmloadRule(t *testing.T) []byte {
	t.Helper()
	paths := []string{
		"../../../../docker/local-rules/powershell_asmload.yara",
		"../../../docker/local-rules/powershell_asmload.yara",
		"../../docker/local-rules/powershell_asmload.yara",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("powershell_asmload.yara not found relative to test dir")
	return nil
}

func TestPS1AsmloadRule_Present(t *testing.T) {
	data := loadPS1AsmloadRule(t)
	if !bytes.Contains(data, []byte("rule PS1_Despaced_Assembly_Load_Loader")) {
		t.Errorf("powershell_asmload.yara missing rule PS1_Despaced_Assembly_Load_Loader")
	}
}

func TestPS1AsmloadRule_Anchors(t *testing.T) {
	data := loadPS1AsmloadRule(t)
	// The four invariants the rule keys on -- if any change, the corpus samples
	// will no longer match.
	for _, anchor := range []string{
		".Replace(' ', '')", // URL de-spacing mechanic (invariant 1)
		"%base64%",          // payload marker literal (invariant 2)
		"Get-Content",       // byte-array loader: file read (invariant 3)
		"-split ','",        // byte-array loader: comma split (invariant 3)
		"Assembly]::Load",   // in-memory .NET execution (invariant 4)
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("powershell_asmload.yara missing anchor %q", anchor)
		}
	}
}

func TestPS1AsmloadRule_HasWideModifier(t *testing.T) {
	// Samples are UTF-16LE -- without `wide` none of the string matches fire.
	// This is GOTCHA-2 from #172: a rule that compiles but never matches its
	// target corpus because the encoding was not considered.
	data := loadPS1AsmloadRule(t)
	if !bytes.Contains(data, []byte("ascii wide")) {
		t.Errorf("powershell_asmload.yara: strings must carry `ascii wide` (UTF-16LE samples)")
	}
}

func TestPS1AsmloadRule_NoBackreference(t *testing.T) {
	// yarac rejects backreferences; compile-rules.sh silently skips the file
	// (GOTCHA-1, #172). Catch at unit speed rather than discovering a missing rule
	// on the live mail host.
	data := loadPS1AsmloadRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`), []byte(`\3`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("powershell_asmload.yara contains backreference %q -- yarac will reject it, rule silently skipped", bad)
		}
	}
}

func TestPS1AsmloadRule_NoNestedUnboundedQuantifier(t *testing.T) {
	// Nested `){N,}` after an unbounded inner group is the catastrophic-
	// backtracking class (#174/#177): the engine retries every split point and
	// blows scan_timeout, fail-opening the file (miss). Guard against regression.
	data := loadPS1AsmloadRule(t)
	for _, bad := range [][]byte{[]byte("){"), []byte("){2,}"), []byte("){3,}")} {
		if bytes.Contains(data, bad) {
			t.Errorf("powershell_asmload.yara contains group-repeat pattern %q -- catastrophic-backtracking risk", bad)
		}
	}
}
