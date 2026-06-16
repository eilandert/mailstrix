package yarad

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestLoadConfigDefaults(t *testing.T) {
	for _, k := range []string{
		"YARAD_HOST", "YARAD_PORT", "YARAD_BACKEND_TIMEOUT", "YARAD_MAX_CONCURRENT",
		"YARAD_MAX_BODY", "YARAD_TOKEN", "YARAD_TOKEN_FILE", "YARAD_RULES_DIR",
		"YARAD_RULES", "YARAD_SCAN_TIMEOUT", "YARAD_VERBOSE", "YARAD_LOG_STDOUT",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	c := LoadConfig()
	if c.Host != "0.0.0.0" || c.Port != 8079 {
		t.Errorf("host/port = %s:%d, want 0.0.0.0:8079", c.Host, c.Port)
	}
	if c.MaxConcurrent != runtime.NumCPU() || c.MaxBody != 8*1024*1024 {
		t.Errorf("concurrency/body = %d/%d (want concurrency=%d)", c.MaxConcurrent, c.MaxBody, runtime.NumCPU())
	}
	if c.BackendTimeout != 6*time.Second || c.ScanTimeout != 10*time.Second {
		t.Errorf("timeouts = %s/%s", c.BackendTimeout, c.ScanTimeout)
	}
	if c.RulesDir != "/rules" {
		t.Errorf("rules dir = %s", c.RulesDir)
	}
}

func TestLoadConfigEnvOverride(t *testing.T) {
	t.Setenv("YARAD_HOST", "127.0.0.1")
	t.Setenv("YARAD_PORT", "9999")
	t.Setenv("YARAD_MAX_CONCURRENT", "32")
	t.Setenv("YARAD_SCAN_TIMEOUT", "2.5")
	t.Setenv("YARAD_TOKEN", "sekrit")
	t.Setenv("YARAD_VERBOSE", "yes")
	c := LoadConfig()
	if c.Host != "127.0.0.1" || c.Port != 9999 || c.MaxConcurrent != 32 {
		t.Errorf("override failed: %+v", c)
	}
	if c.ScanTimeout != 2500*time.Millisecond {
		t.Errorf("scan timeout = %s, want 2.5s", c.ScanTimeout)
	}
	if c.Token != "sekrit" || !c.Verbose {
		t.Errorf("token/verbose = %q/%t", c.Token, c.Verbose)
	}
}

func TestEnvOrFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "tok")
	if err := os.WriteFile(f, []byte("  filetoken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YARAD_TOKEN", "envtoken")
	t.Setenv("YARAD_TOKEN_FILE", f)
	if got := LoadConfig().Token; got != "filetoken" {
		t.Errorf("_FILE should win and be trimmed, got %q", got)
	}
}

func TestSanitizeClamps(t *testing.T) {
	c := &Config{Host: "x", Port: 0, MaxConcurrent: -1, BackendTimeout: 0, ScanTimeout: -1, MaxBody: 0}
	c.sanitize()
	if c.Port != 8079 || c.MaxConcurrent != runtime.NumCPU() || c.BackendTimeout != 6*time.Second ||
		c.ScanTimeout != 10*time.Second || c.MaxBody != 8*1024*1024 {
		t.Errorf("sanitize did not clamp: %+v (want concurrency=%d)", c, runtime.NumCPU())
	}
}

func TestEnvBool(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "on", "TRUE", "On"} {
		t.Setenv("X", v)
		if !envBool("X") {
			t.Errorf("envBool(%q) = false", v)
		}
	}
	for _, v := range []string{"0", "false", "no", "", "maybe"} {
		t.Setenv("X", v)
		if envBool("X") {
			t.Errorf("envBool(%q) = true", v)
		}
	}
}
