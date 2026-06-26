package feodo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleCSV = `# Feodo Tracker Botnet C2 IP Blocklist
# Generated: 2024-01-02
# Entries: 3
# ip_address,dst_port,last_online,malware
"1.2.3.4","4444","2024-01-01","Emotet"
"5.6.7.8","8080","2024-01-02","TrickBot"
"10.20.30.40","443","2024-01-01","AgentTesla"
`

func testChecker(t *testing.T) *Checker {
	t.Helper()
	rs, err := parseFeed(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{logf: func(string, ...any) {}}
	c.rs.Store(rs)
	return c
}

func TestParseFeed(t *testing.T) {
	rs, err := parseFeed(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.ips) != 3 {
		t.Errorf("ips=%d want 3", len(rs.ips))
	}
	for _, ip := range []string{"1.2.3.4", "5.6.7.8", "10.20.30.40"} {
		if _, ok := rs.ips[ip]; !ok {
			t.Errorf("IP %s missing", ip)
		}
	}
}

func TestCheckIPInURL(t *testing.T) {
	hits := testChecker(t).Check([]byte("download from http://1.2.3.4/payload.exe now"), 64)
	if len(hits) != 1 || hits[0].Deobf {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].IP != "1.2.3.4" {
		t.Errorf("IP=%s want 1.2.3.4", hits[0].IP)
	}
	if hits[0].Rule() != "FEODO_CC_IP" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckDeobf(t *testing.T) {
	hits := testChecker(t).Check([]byte("hxxp://1.2.3[.]4/payload.exe"), 64)
	if len(hits) != 1 || !hits[0].Deobf {
		t.Fatalf("deobf hits=%+v", hits)
	}
	if hits[0].Rule() != "FEODO_CC_IP_DEOBF" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckDomainNotMatched(t *testing.T) {
	// Feodo only matches IP hosts, not domain names.
	hits := testChecker(t).Check([]byte("https://evil.example.com/path"), 64)
	if len(hits) != 0 {
		t.Errorf("domain URL should not match Feodo blocklist: %+v", hits)
	}
}

func TestCheckClean(t *testing.T) {
	hits := testChecker(t).Check([]byte("http://9.9.9.9/ok"), 64)
	if len(hits) != 0 {
		t.Errorf("unlisted IP matched: %+v", hits)
	}
}

func TestCheckBudget(t *testing.T) {
	hits := testChecker(t).Check([]byte("https://9.9.9.9/ok http://1.2.3.4/bad"), 1)
	if len(hits) != 0 {
		t.Errorf("budget not honoured: %+v", hits)
	}
}

func TestNewDisabled(t *testing.T) {
	if New(false, "", 0, "", func(string, ...any) {}) != nil {
		t.Error("enabled=false must return nil")
	}
}

func TestWarmStartFromCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "feodo.csv"), []byte(sampleCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(true, "", 0, dir, func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil")
	}
	hits := c.Check([]byte("http://1.2.3.4/evil"), 64)
	if len(hits) == 0 {
		t.Error("warm-started feed should match before any network refresh")
	}
}

func TestIsIP(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":   true,
		"10.0.0.1":  true,
		"255.0.0.1": true,
		"evil.com":  false,
		"1.2.3":     false,
		"1.2.3.4.5": false,
		"":          false,
		"1.2.3.x":   false,
	}
	for in, want := range cases {
		if got := isIP(in); got != want {
			t.Errorf("isIP(%q)=%v want %v", in, got, want)
		}
	}
}

func TestCloseNilSafeAndIdempotent(t *testing.T) {
	var nilC *Checker
	nilC.Close()

	c := New(true, "", 0, "", func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil")
	}
	c.Close()
	c.Close()
	select {
	case <-c.stop:
	default:
		t.Fatal("Close did not close the stop channel")
	}
}
