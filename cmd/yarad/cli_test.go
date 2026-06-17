package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// eicarRule is a minimal compilable YARA rule; eicarPayload is the string it
// matches. Reused across the scan/check-rules tests so a match is deterministic.
const eicarRule = `
rule EICAR_Test_File : test
{
    strings:
        $e = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $e
}
`

const eicarPayload = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// withRules writes a one-rule dir and points YARAD_RULES_DIR at it for the test,
// restoring the previous value afterward. The CLI subcommands build their own
// scanner from config, so the rule set is supplied through the environment.
func withRules(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YARAD_RULES_DIR", dir)
	// Make sure a precompiled bundle from the environment can't win over the dir.
	t.Setenv("YARAD_RULES", "")
}

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. CLI output goes to stdout, so the tests assert on it directly.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

func TestCheckRulesOK(t *testing.T) {
	withRules(t, eicarRule)
	var code int
	out := captureStdout(t, func() { code = cmdCheckRules(nil) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "OK") || !strings.Contains(out, "1 rules loaded") {
		t.Errorf("output = %q", out)
	}
}

func TestCheckRulesFail(t *testing.T) {
	// An empty rules dir compiles nothing => NewScanner errors => exit 1.
	t.Setenv("YARAD_RULES_DIR", t.TempDir())
	t.Setenv("YARAD_RULES", "")
	code := cmdCheckRules(nil)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

func TestScanFileMatch(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(f, []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{f}) })
	if code != 1 { // a match forces exit 1
		t.Fatalf("exit = %d, want 1 (match)", code)
	}
	if !strings.Contains(out, "MATCH EICAR_Test_File") {
		t.Errorf("output = %q", out)
	}
}

func TestScanFileClean(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "clean.txt")
	if err := os.WriteFile(f, []byte("nothing to see here"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{f}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (clean)", code)
	}
	if !strings.Contains(out, "CLEAN") {
		t.Errorf("output = %q", out)
	}
}

func TestScanQuietSuppressesClean(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "clean.txt")
	if err := os.WriteFile(f, []byte("benign"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { cmdScan([]string{"-quiet", f}) })
	if strings.Contains(out, "CLEAN") {
		t.Errorf("-quiet should suppress CLEAN lines: %q", out)
	}
}

func TestScanDirRecurses(t *testing.T) {
	withRules(t, eicarRule)
	root := t.TempDir()
	sub := filepath.Join(root, "cur")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "msg:2,S"), []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "clean"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{root}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (one member matched)", code)
	}
	if !strings.Contains(out, "msg:2,S") || !strings.Contains(out, "MATCH") {
		t.Errorf("recursed output missing the maildir member match: %q", out)
	}
}

func TestScanStdin(t *testing.T) {
	withRules(t, eicarRule)
	// Feed the EICAR payload on stdin (the `yarad scan - < maildirfile` case).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(eicarPayload); err != nil {
		t.Fatal(err)
	}
	w.Close()
	origIn := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origIn }()

	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{"-"}) })
	if code != 1 {
		t.Fatalf("stdin exit = %d, want 1", code)
	}
	if !strings.Contains(out, "MATCH") {
		t.Errorf("stdin output = %q", out)
	}
}

func TestScanJSON(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "s.txt")
	if err := os.WriteFile(f, []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { cmdScan([]string{"-json", f}) })
	if !strings.Contains(out, `"matches"`) || !strings.Contains(out, "EICAR_Test_File") {
		t.Errorf("json output = %q", out)
	}
}

func TestScanMissingFileErrors(t *testing.T) {
	withRules(t, eicarRule)
	code := cmdScan([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (read error)", code)
	}
}

func TestExtractStreamsAndExit(t *testing.T) {
	// A plain text input is not a recognised container => zero streams => exit 1.
	f := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(f, []byte("just text"), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdExtract([]string{f}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (nothing carved)", code)
	}
	if !strings.Contains(out, "container:") || !strings.Contains(out, "streams:") {
		t.Errorf("extract report missing fields: %q", out)
	}
}

func TestExtractMissingFileErrors(t *testing.T) {
	code := cmdExtract([]string{filepath.Join(t.TempDir(), "nope")})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

// TestScanSymlinkedDirRoot guards the Codex P2 fix: a symlink whose target is a
// directory must be walked (os.Stat follows it, but filepath.WalkDir would not
// descend the symlinked root) so a maildir reached via a symlink isn't silently
// reported clean.
func TestScanSymlinkedDirRoot(t *testing.T) {
	withRules(t, eicarRule)
	realDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(realDir, "evil"), []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "maildir-link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{link}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (symlinked dir must be scanned, member matched)", code)
	}
	if !strings.Contains(out, "MATCH") {
		t.Errorf("symlinked-dir scan missed the member: %q", out)
	}
}

// TestScanMaxBodyZeroStillBounded guards the Codex P2 fix: a non-positive
// -max-body must not disable the read cap. We can't easily assert the cap size
// here, but the scan must still complete and not error — confirming the clamp
// keeps a valid LimitReader in place.
func TestScanMaxBodyZeroStillBounded(t *testing.T) {
	withRules(t, eicarRule)
	f := filepath.Join(t.TempDir(), "s.txt")
	if err := os.WriteFile(f, []byte(eicarPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = cmdScan([]string{"-max-body=0", f}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (clamped cap, payload still scanned)", code)
	}
	if !strings.Contains(out, "MATCH") {
		t.Errorf("output = %q", out)
	}
}
