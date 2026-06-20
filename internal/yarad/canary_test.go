package yarad

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCanaryTagsAllMatches verifies that with canary=true every match gets
// yarad_canary=1 in its Meta map.
func TestCanaryTagsAllMatches(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{RulesDir: dir, ScanTimeout: 0, Canary: true}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	m, err := scanT(s, eicar(), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 match, got %d", len(m))
	}
	if m[0].Meta["yarad_canary"] != "1" {
		t.Errorf("canary match not tagged: meta=%v", m[0].Meta)
	}
}

// TestCanaryOffNoTag verifies that with canary=false matches do NOT get
// yarad_canary.
func TestCanaryOffNoTag(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{RulesDir: dir, ScanTimeout: 0, Canary: false}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	m, err := scanT(s, eicar(), ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 match, got %d", len(m))
	}
	if _, ok := m[0].Meta["yarad_canary"]; ok {
		t.Errorf("canary tag present when canary is off: meta=%v", m[0].Meta)
	}
}

// TestCanaryEnvParsing verifies YARAD_CANARY env parsing.
func TestCanaryEnvParsing(t *testing.T) {
	t.Setenv("YARAD_CANARY", "1")
	c := LoadConfig()
	if !c.Canary {
		t.Error("YARAD_CANARY=1 should set Canary=true")
	}
}

// TestReloadDenylistMergesFile verifies that ReloadDenylist reads a file and
// merges its entries with the env-based baseDenylist.
func TestReloadDenylistMergesFile(t *testing.T) {
	dir := writeRules(t, eicarRule)
	// Write a denylist file with one rule name.
	denyFile := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(denyFile, []byte("# comment\n\nFromFile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		RulesDir:     dir,
		ScanTimeout:  0,
		RuleDenylist: map[string]struct{}{"fromenv": {}},
		DenylistFile: denyFile,
	}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	// Both env and file entries should be in the merged denylist.
	if _, ok := (*s.denylist.Load())["fromenv"]; !ok {
		t.Error("env denylist entry missing after merge")
	}
	if _, ok := (*s.denylist.Load())["fromfile"]; !ok {
		t.Error("file denylist entry missing after merge (should be lowercased)")
	}
}

// TestReloadDenylistMissingFile verifies that a missing denylist file logs a
// warning but does not crash (fail-open).
func TestReloadDenylistMissingFile(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{
		RulesDir:     dir,
		ScanTimeout:  0,
		RuleDenylist: map[string]struct{}{"fromenv": {}},
		DenylistFile: filepath.Join(t.TempDir(), "nonexistent.txt"),
	}
	cfg.sanitize()
	var warned bool
	logf := func(format string, a ...any) {
		if len(format) > 7 && format[:7] == "WARNING" {
			warned = true
		}
	}
	s, err := NewScanner(cfg, logf)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if !warned {
		t.Error("expected a warning for missing denylist file")
	}
	// Env denylist should still be intact.
	if _, ok := (*s.denylist.Load())["fromenv"]; !ok {
		t.Error("env denylist lost after missing-file reload")
	}
}

// TestReloadDenylistNoFile verifies that with no DenylistFile configured,
// ReloadDenylist is a no-op.
func TestReloadDenylistNoFile(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{
		RulesDir:     dir,
		ScanTimeout:  0,
		RuleDenylist: map[string]struct{}{"fromenv": {}},
	}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	// Calling again should be a no-op.
	s.ReloadDenylist()
	if _, ok := (*s.denylist.Load())["fromenv"]; !ok {
		t.Error("env denylist entry should still be present")
	}
}

// TestDenylistFileEnvParsing verifies YARAD_DENYLIST_FILE env parsing.
func TestDenylistFileEnvParsing(t *testing.T) {
	t.Setenv("YARAD_DENYLIST_FILE", "/tmp/deny.txt")
	c := LoadConfig()
	if c.DenylistFile != "/tmp/deny.txt" {
		t.Errorf("DenylistFile = %q, want /tmp/deny.txt", c.DenylistFile)
	}
}
