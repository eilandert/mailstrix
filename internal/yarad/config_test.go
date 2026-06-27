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
	if c.BackendTimeout != time.Second || c.ScanTimeout != 8*time.Second {
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

// YARAD_MAX_CONCURRENT="auto" (any case) must resolve to the CPU count, the same
// as leaving it unset, so operators can write the literal default explicitly.
// The admission gate defaults to 2× scan concurrency, honours an explicit value,
// and is bumped up if set below scan concurrency (which would cap scan slots).
func TestMaxInflightDefault(t *testing.T) {
	c := &Config{MaxConcurrent: 4}
	c.sanitize()
	if c.MaxInflight != 8 {
		t.Errorf("default MaxInflight=%d want 8 (2×4)", c.MaxInflight)
	}
	c = &Config{MaxConcurrent: 4, MaxInflight: 20}
	c.sanitize()
	if c.MaxInflight != 20 {
		t.Errorf("explicit MaxInflight=%d want 20", c.MaxInflight)
	}
	c = &Config{MaxConcurrent: 10, MaxInflight: 3}
	c.sanitize()
	if c.MaxInflight != 20 {
		t.Errorf("MaxInflight below concurrency=%d want 20 (bumped)", c.MaxInflight)
	}
}

func TestLoadConfigMaxConcurrentAuto(t *testing.T) {
	for _, v := range []string{"auto", "AUTO", "Auto"} {
		t.Setenv("YARAD_MAX_CONCURRENT", v)
		if c := LoadConfig(); c.MaxConcurrent != runtime.NumCPU() {
			t.Errorf("%q -> MaxConcurrent=%d, want %d", v, c.MaxConcurrent, runtime.NumCPU())
		}
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
	if c.Port != 8079 || c.MaxConcurrent != runtime.NumCPU() || c.BackendTimeout != time.Second ||
		c.ScanTimeout != 8*time.Second || c.MaxBody != 8*1024*1024 {
		t.Errorf("sanitize did not clamp: %+v (want concurrency=%d)", c, runtime.NumCPU())
	}
}

// TestFinalizeClampsScanTimeout guards the CLI flag overlay bug: a non-positive
// -scan-timeout passed after LoadConfig must be re-clamped to 8s by Finalize
// so the libyara/extraction deadline is never disabled. Finalize must be
// idempotent — calling it twice on a valid config must not change values.
func TestFinalizeClampsScanTimeout(t *testing.T) {
	cases := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"zero disables guard", 0, 8 * time.Second},
		{"negative disables guard", -1 * time.Second, 8 * time.Second},
		{"positive preserved", 5 * time.Second, 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				Host:           "0.0.0.0",
				Port:           8079,
				MaxConcurrent:  1,
				BackendTimeout: time.Second,
				ScanTimeout:    tc.timeout,
				MaxBody:        8 * 1024 * 1024,
			}
			c.Finalize()
			if c.ScanTimeout != tc.want {
				t.Errorf("after Finalize: ScanTimeout = %s, want %s", c.ScanTimeout, tc.want)
			}
			// Idempotency: second call must not change a valid result.
			before := c.ScanTimeout
			c.Finalize()
			if c.ScanTimeout != before {
				t.Errorf("Finalize not idempotent: %s -> %s", before, c.ScanTimeout)
			}
		})
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

// TestTokenDisableSentinels: the explicit "no auth" sentinels (and unset)
// normalise to an empty token so /scan runs open; a real secret is kept as-is.
func TestTokenDisableSentinels(t *testing.T) {
	for _, in := range []string{"", "none", "NONE", "off", "0", "disabled", "false", "  none  "} {
		if got := normalizeToken(in); got != "" {
			t.Errorf("normalizeToken(%q) = %q, want \"\" (auth disabled)", in, got)
		}
	}
	for _, in := range []string{"s3cret", "hunter2", "none-but-longer"} {
		if got := normalizeToken(in); got != in {
			t.Errorf("normalizeToken(%q) = %q, want it kept", in, got)
		}
	}
	// Round-trip through sanitize() (covers the flag path too).
	c := &Config{Token: "none"}
	c.sanitize()
	if c.Token != "" {
		t.Errorf("sanitize kept disable sentinel: %q", c.Token)
	}
}
