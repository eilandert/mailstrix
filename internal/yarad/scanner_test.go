package yarad

import (
	"os"
	"path/filepath"
	"testing"
)

// eicar reconstructs the standard EICAR antivirus test string from fragments so
// the test binary itself is not flagged by an on-access scanner in the repo or
// CI. It is the canonical harmless test pattern, not real malware.
func eicar() []byte {
	return []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}` + `$EICAR-STANDARD-` +
		`ANTIVIRUS-TEST-FILE!` + `$H+H*`)
}

const eicarRule = `
rule EICAR_Test_File : test
{
    meta:
        description = "EICAR antivirus test pattern"
        severity = "low"
    strings:
        $eicar = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $eicar
}
`

func writeRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newScanner(t *testing.T, dir string) *Scanner {
	t.Helper()
	cfg := &Config{RulesDir: dir, ScanTimeout: 0}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

func TestScannerCompileAndCount(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	if s.RuleCount() != 1 {
		t.Errorf("rule count = %d, want 1", s.RuleCount())
	}
}

func TestScannerMatch(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	m, err := s.Scan(eicar())
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[0].Rule != "EICAR_Test_File" {
		t.Fatalf("matches = %+v", m)
	}
	if m[0].Meta["description"] == "" {
		t.Errorf("meta not propagated: %+v", m[0].Meta)
	}
	if len(m[0].Tags) != 1 || m[0].Tags[0] != "test" {
		t.Errorf("tags = %v, want [test]", m[0].Tags)
	}
}

func TestScannerNoMatch(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	m, err := s.Scan([]byte("a perfectly innocent email body"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("clean input matched: %+v", m)
	}
}

func TestScannerEmptyDirIsError(t *testing.T) {
	cfg := &Config{RulesDir: t.TempDir(), ScanTimeout: 0}
	cfg.sanitize()
	if _, err := NewScanner(cfg, func(string, ...any) {}); err == nil {
		t.Error("empty rules dir should error at startup")
	}
}

func TestScannerSkipsBadFileKeepsGood(t *testing.T) {
	// A dir with one good and one unparseable file must load the good rules and
	// skip the bad one, not abort the whole compile. This is the real public-
	// ruleset case (a stray cuckoo/magic import or bad syntax among hundreds).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.yar"), []byte(eicarRule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yar"), []byte("rule oops { this is not yara }"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newScanner(t, dir)
	if s.RuleCount() != 1 {
		t.Fatalf("rule count = %d, want 1 (good kept, bad skipped)", s.RuleCount())
	}
	m, err := s.Scan(eicar())
	if err != nil || len(m) != 1 {
		t.Errorf("good rule should still match: %+v err=%v", m, err)
	}
}

func TestScannerBrokenRuleKeepsOld(t *testing.T) {
	dir := writeRules(t, eicarRule)
	s := newScanner(t, dir)
	// Overwrite with a syntactically broken rule, then reload: must fail and
	// keep the previous (working) set active.
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte("rule broken {"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Error("broken reload should error")
	}
	m, err := s.Scan(eicar())
	if err != nil || len(m) != 1 {
		t.Errorf("old ruleset should still match after failed reload: %+v err=%v", m, err)
	}
}
