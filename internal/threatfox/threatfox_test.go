package threatfox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleCSV = `# Dump generated 2024-01-02
# id,ioc_type,ioc_value,threat_type,fk_threat_type,malware,fk_malware,malware_alias,malware_printable,first_seen_utc,last_seen_utc,confidence_level,anonymized,tags,credits,reference
"1","url","http://c2.evil.test/payload.exe","botnet_cc","1","AgentTesla","1","AgentTesla","AgentTesla","2024-01-01 00:00:00 UTC","2024-01-02 00:00:00 UTC","75","","exe","anon","https://threatfox.abuse.ch/ioc/1/"
"2","domain","malicious.domain.test","botnet_cc","1","Emotet","2","Emotet","Emotet","2024-01-01 00:00:00 UTC","","90","","","anon","https://threatfox.abuse.ch/ioc/2/"
"3","ip:port","10.20.30.40:4444","botnet_cc","1","TrickBot","3","TrickBot","TrickBot","2024-01-01 00:00:00 UTC","","80","","","anon","https://threatfox.abuse.ch/ioc/3/"
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
	// URL row: "http://c2.evil.test/payload.exe" → urls + domains
	if len(rs.urls) != 1 {
		t.Errorf("urls=%d want 1", len(rs.urls))
	}
	// domain row: "malicious.domain.test" + host from url row = 2 domains
	if len(rs.domains) != 2 {
		t.Errorf("domains=%d want 2 (url-host + domain-row)", len(rs.domains))
	}
	if _, ok := rs.domains["malicious.domain.test"]; !ok {
		t.Error("domain malicious.domain.test missing")
	}
	if _, ok := rs.domains["c2.evil.test"]; !ok {
		t.Error("url-derived host c2.evil.test missing from domains")
	}
}

func TestCheckExactURL(t *testing.T) {
	hits := testChecker(t).Check([]byte("click http://c2.evil.test/payload.exe now"), 64)
	if len(hits) != 1 || hits[0].Host || hits[0].Deobf {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].Rule() != "THREATFOX_IOC_URL" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckDomainMatch(t *testing.T) {
	// Different path on known-bad domain → domain-level hit.
	hits := testChecker(t).Check([]byte("see https://malicious.domain.test/other/path"), 64)
	if len(hits) != 1 || !hits[0].Host {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].Rule() != "THREATFOX_IOC_DOMAIN" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckDeobf(t *testing.T) {
	hits := testChecker(t).Check([]byte("hxxp://c2.evil[.]test/payload.exe"), 64)
	if len(hits) != 1 || !hits[0].Deobf {
		t.Fatalf("deobf hits=%+v", hits)
	}
	if hits[0].Rule() != "THREATFOX_IOC_URL_DEOBF" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckClean(t *testing.T) {
	hits := testChecker(t).Check([]byte("nothing bad here https://good.example/ok"), 64)
	if len(hits) != 0 {
		t.Errorf("clean buffer matched: %+v", hits)
	}
}

func TestCheckBudget(t *testing.T) {
	hits := testChecker(t).Check([]byte("https://good.example/a http://c2.evil.test/payload.exe"), 1)
	if len(hits) != 0 {
		t.Errorf("budget not honoured: %+v", hits)
	}
}

func TestNewDisabledNoKey(t *testing.T) {
	if New("", 0, "", func(string, ...any) {}) != nil {
		t.Error("empty key must disable the checker (nil)")
	}
}

func TestWarmStartFromCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "threatfox.csv"), []byte(sampleCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New("bogus-key", 0, dir, func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil with a key set")
	}
	hits := c.Check([]byte("click http://c2.evil.test/payload.exe now"), 64)
	if len(hits) == 0 {
		t.Error("warm-started feed should match the cached URL before any network refresh")
	}
}

func TestCloseNilSafeAndIdempotent(t *testing.T) {
	var nilC *Checker
	nilC.Close()

	c := New("bogus-key", 0, "", func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil for a non-empty key")
	}
	c.Close()
	c.Close()
	select {
	case <-c.stop:
	default:
		t.Fatal("Close did not close the stop channel")
	}
}
