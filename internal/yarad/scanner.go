package yarad

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	yara "github.com/hillu/go-yara/v4"
)

// Match is one matched YARA rule, reported back to the rspamd plugin. Tags and
// the "meta" map come straight from the rule definition so the plugin can score
// or branch on them without yarad knowing anything rule-specific.
type Match struct {
	Rule string            `json:"rule"`
	Tags []string          `json:"tags,omitempty"`
	Meta map[string]string `json:"meta,omitempty"`
}

// Scanner compiles a set of YARA rules once and scans message bytes against
// them. The compiled *yara.Rules is immutable once built, so reloads build a
// fresh set and swap the pointer atomically — in-flight scans keep using the
// old set until they finish, new scans pick up the new one. No scan ever holds
// a lock for its (potentially slow) duration.
type Scanner struct {
	rules       atomic.Pointer[yara.Rules]
	scanTimeout time.Duration
	logf        func(string, ...any)

	mu      sync.Mutex // serializes Reload so two SIGHUPs can't compile at once
	srcDir  string
	srcFile string // precompiled bundle; wins over srcDir when set
	count   atomic.Int64
	fp      atomic.Pointer[string] // ruleset fingerprint, changes on reload
}

// NewScanner builds a scanner and performs the initial compile/load. It returns
// an error only when no rules at all could be loaded — a service with zero
// rules is a misconfiguration the operator must see at startup, not a silent
// "everything is clean".
func NewScanner(cfg *Config, logf func(string, ...any)) (*Scanner, error) {
	s := &Scanner{
		scanTimeout: cfg.ScanTimeout,
		logf:        logf,
		srcDir:      cfg.RulesDir,
		srcFile:     cfg.RulesPath,
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// RuleCount reports how many rules are in the active set (for /health and logs).
func (s *Scanner) RuleCount() int64 { return s.count.Load() }

// Reload (re)compiles the rule set and atomically swaps it in. A failure leaves
// the previous set active — a broken edit to the rules dir must never disarm a
// running scanner. Safe to call from a SIGHUP handler concurrently with scans.
func (s *Scanner) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		rules *yara.Rules
		err   error
	)
	if s.srcFile != "" {
		rules, err = yara.LoadRules(s.srcFile)
	} else {
		rules, err = compileDir(s.srcDir, s.logf)
	}
	if err != nil {
		s.logf("ERROR reload failed, keeping previous rules: %v", err)
		return err
	}

	list := rules.GetRules()
	s.rules.Swap(rules)
	s.count.Store(int64(len(list)))
	fp := fingerprint(list)
	s.fp.Store(&fp)
	// The previous *yara.Rules is intentionally NOT Destroy()ed here: an in-flight
	// scan may still hold the pointer it loaded before the swap, and freeing the
	// native rules under it would crash. go-yara registers a runtime finalizer on
	// *Rules (via runtime.SetFinalizer in Compile/GetRules), so the old set is
	// freed by the GC once no goroutine references it. Reloads are infrequent, so
	// finalizer-driven cleanup is the safe choice over manual/refcounted retire.
	src := s.srcDir
	if s.srcFile != "" {
		src = s.srcFile
	}
	s.logf("loaded %d YARA rules from %s (fp=%s)", s.count.Load(), src, fp)
	return nil
}

// Fingerprint returns a short hash identifying the active rule set. It is part
// of the verdict cache key, so a reload that changes the rules changes the
// fingerprint and old cached verdicts (in-process L1 and shared Redis L2) are no
// longer hit — they orphan and TTL-expire instead of serving a stale "clean".
func (s *Scanner) Fingerprint() string {
	if p := s.fp.Load(); p != nil {
		return *p
	}
	return ""
}

// fingerprint hashes the sorted rule identities (namespace + identifier) so the
// same compiled rule set always yields the same value across processes/replicas,
// and any add/remove/rename changes it.
func fingerprint(rules []yara.Rule) string {
	ids := make([]string, 0, len(rules))
	for i := range rules {
		ids = append(ids, rules[i].Namespace()+"/"+rules[i].Identifier())
	}
	sort.Strings(ids)
	h := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return hex.EncodeToString(h[:8]) // 16 hex chars is plenty to distinguish rule sets
}

// compileDir compiles every *.yar / *.yara file under dir into one rule set.
// Files are added by namespace = their base name so identically named rules in
// different files don't collide.
//
// Public rulesets (YARA-Forge, signature-base, ANY.RUN) inevitably contain a
// few files this build can't compile: a rule importing a module we didn't build
// in (cuckoo, magic), or a syntax the linked libyara version rejects. One such
// file must NOT disarm the whole scanner, so each file is validated in a
// throwaway compiler first and only added to the real set if it compiles
// clean; bad files are logged and skipped. It is an error only if NOTHING
// compiles (a misconfigured rules dir, not a single rotten rule).
func compileDir(dir string, logf func(string, ...any)) (*yara.Rules, error) {
	var files []string
	for _, ext := range []string{"*.yar", "*.yara"} {
		m, _ := filepath.Glob(filepath.Join(dir, ext))
		files = append(files, m...)
	}
	sort.Strings(files) // deterministic namespace ordering
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.yar/*.yara files in %s", dir)
	}

	c, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("new compiler: %w", err)
	}
	added, skipped := 0, 0
	for _, f := range files {
		if compileErr := fileCompiles(f); compileErr != nil {
			skipped++
			logf("skip unparseable rule file %s: %v", filepath.Base(f), compileErr)
			continue
		}
		fh, err := os.Open(f) // #nosec G304 -- operator rules dir, not attacker input
		if err != nil {
			logf("skip unreadable rule file %s: %v", filepath.Base(f), err)
			skipped++
			continue
		}
		err = c.AddFile(fh, filepath.Base(f))
		_ = fh.Close()
		if err != nil {
			// Should be rare: fileCompiles already validated it in isolation.
			logf("skip rule file %s (rejected by shared compiler): %v", filepath.Base(f), err)
			skipped++
			continue
		}
		added++
	}
	if added == 0 {
		return nil, fmt.Errorf("no compilable *.yar/*.yara files in %s (%d skipped)", dir, skipped)
	}
	rules, err := c.GetRules()
	if err != nil {
		return nil, fmt.Errorf("get rules: %w", err)
	}
	if skipped > 0 {
		logf("compiled %d rule files, skipped %d unparseable", added, skipped)
	}
	return rules, nil
}

// fileCompiles validates one rule file in an isolated compiler so a single bad
// file (unknown module, bad syntax) can be skipped without poisoning the shared
// compiler the rest of the set is built in.
func fileCompiles(path string) error {
	c, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	defer c.Destroy()
	fh, err := os.Open(path) // #nosec G304 -- operator rules dir, not attacker input
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := c.AddFile(fh, filepath.Base(path)); err != nil {
		return err
	}
	_, err = c.GetRules()
	return err
}

// Scan runs the active rule set over buf and returns the matched rules. It is
// safe for concurrent use. A scan failure (timeout, libyara error) returns the
// error; the server treats that as "no match" but logs it, so a scanner problem
// never blocks mail (fail-open, matching the gozer contract).
func (s *Scanner) Scan(buf []byte) ([]Match, error) {
	rules := s.rules.Load()
	if rules == nil {
		return nil, fmt.Errorf("no rules loaded")
	}
	var mr yara.MatchRules
	// ScanMem takes a per-scan wall-clock budget; yara.MatchRules implements
	// ScanCallback and collects the matched rules. flags=0 = default scan.
	if err := rules.ScanMem(buf, 0, s.scanTimeout, &mr); err != nil {
		return nil, err
	}
	out := make([]Match, 0, len(mr))
	for _, m := range mr {
		meta := make(map[string]string, len(m.Metas))
		for _, kv := range m.Metas {
			meta[kv.Identifier] = fmt.Sprintf("%v", kv.Value)
		}
		if len(meta) == 0 {
			meta = nil
		}
		out = append(out, Match{Rule: m.Rule, Tags: m.Tags, Meta: meta})
	}
	return out, nil
}
