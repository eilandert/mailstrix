// Package feodo adds an abuse.ch Feodo Tracker IP-blocklist check to yarad.
// Feodo Tracker tracks botnet C&C servers (Emotet, TrickBot, AgentTesla, …);
// the blocklist is a CSV of known-malicious IP:port pairs.
//
// Design mirrors internal/urlhaus (same fetch/refresh/cache pattern) but with
// one simplification: Feodo is a public feed (no Auth-Key required) and stores
// only IP addresses. A URL whose host is a raw IP listed in the blocklist is a
// strong signal — botnet C&C payloads often hardcode IP:port rather than a
// domain to avoid DNS-based blocking.
//
// The feed URL (https://feodotracker.abuse.ch/downloads/ipblocklist.csv) is
// public. A key is not required; New accepts an empty key and still starts the
// refresher. Callers that supply a non-empty abuse.ch key get it attached as an
// Auth-Key header for potential future access controls on the feed.
package feodo

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eilandert/rspamd-yarad/internal/atomicio"
)

const (
	feedURL        = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
	minRefresh     = 5 * time.Minute
	defaultRefresh = 360 * time.Minute
	fetchTimeout   = 60 * time.Second
	maxFeedBytes   = 16 << 20
)

// Hit is one URL in a scanned buffer whose host IP matched the Feodo blocklist.
type Hit struct {
	URL   string // the matched (normalized) URL containing the blocked IP
	IP    string // the blocked IP (no port)
	Deobf bool   // found only after defanging
}

// Rule returns the synthetic rule name for this hit.
func (h Hit) Rule() string {
	if h.Deobf {
		return "FEODO_CC_IP_DEOBF"
	}
	return "FEODO_CC_IP"
}

// Metrics is a snapshot for /metrics.
type Metrics struct {
	Enabled         bool
	FeedIPs         int64
	LastRefreshUnix int64
	RefreshFailures uint64
	Lookups         uint64
	Hits            uint64
}

type ruleset struct {
	ips map[string]struct{} // bare IP addresses (no port)
}

// Checker holds the cached blocklist and serves lookups.
type Checker struct {
	rs        atomic.Pointer[ruleset]
	key       string // optional abuse.ch key (may be empty)
	refresh   time.Duration
	client    *http.Client
	logf      func(string, ...any)
	cachePath string

	lastRefresh atomic.Int64
	failures    atomic.Uint64
	lookups     atomic.Uint64
	hits        atomic.Uint64

	stop     chan struct{}
	stopOnce sync.Once
}

// New builds a Checker and starts its background refresher. The feed is public;
// key may be empty. enabled must be true to start (allows callers to gate on a
// config flag without the nil-check pattern used for key-gated feeds).
func New(enabled bool, key string, refresh time.Duration, cacheDir string, logf func(string, ...any)) *Checker {
	if !enabled {
		return nil
	}
	if refresh <= 0 {
		refresh = defaultRefresh
	}
	if refresh < minRefresh {
		refresh = minRefresh
	}
	c := &Checker{
		key:     strings.TrimSpace(key),
		refresh: refresh,
		stop:    make(chan struct{}),
		client:  &http.Client{Timeout: fetchTimeout},
		logf:    logf,
	}
	if cacheDir != "" {
		c.cachePath = filepath.Join(cacheDir, "feodo.csv")
	}
	c.rs.Store(&ruleset{ips: map[string]struct{}{}})
	c.warmStart()
	go c.refreshLoop()
	return c
}

func (c *Checker) warmStart() {
	if c.cachePath == "" {
		return
	}
	b, ok := atomicio.ReadCached(c.cachePath)
	if !ok {
		return
	}
	rs, err := parseFeed(bytes.NewReader(b))
	if err != nil {
		c.logf("feodo warm-start parse failed (ignoring cached feed): %v", err)
		return
	}
	c.rs.Store(rs)
	c.logf("feodo warm-start from cache: %d IPs", len(rs.ips))
}

func (c *Checker) refreshLoop() {
	if err := c.refreshOnce(); err != nil {
		c.failures.Add(1)
		c.logf("feodo initial feed fetch failed: %v", err)
	}
	t := time.NewTicker(c.refresh)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if err := c.refreshOnce(); err != nil {
				c.failures.Add(1)
				c.logf("feodo feed refresh failed (keeping previous set): %v", err)
			}
		}
	}
}

// Close stops the background refresher. Safe on nil and multiple calls.
func (c *Checker) Close() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() { close(c.stop) })
}

func (c *Checker) refreshOnce() error {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return err
	}
	if c.key != "" {
		req.Header.Set("Auth-Key", c.key)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &statusError{resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return err
	}
	rs, err := parseFeed(bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.rs.Store(rs)
	c.lastRefresh.Store(time.Now().Unix())
	if c.cachePath != "" {
		if err := atomicio.WriteWithBackup(c.cachePath, body, 0o600); err != nil {
			c.logf("feodo feed cache write failed (non-fatal): %v", err)
		}
	}
	c.logf("feodo blocklist loaded: %d IPs", len(rs.ips))
	return nil
}

type statusError struct{ code int }

func (e *statusError) Error() string { return "feodo feed HTTP " + strconv.Itoa(e.code) }

// parseFeed reads the Feodo Tracker IP blocklist CSV.
// Format (# comments): ip_address,dst_port,last_online,malware
// We extract bare IP addresses from column 0.
func parseFeed(r io.Reader) (*ruleset, error) {
	rs := &ruleset{ips: make(map[string]struct{})}
	cr := csv.NewReader(io.LimitReader(r, maxFeedBytes))
	cr.Comment = '#'
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.ReuseRecord = true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) < 1 {
			continue
		}
		ip := strings.TrimSpace(rec[0])
		if isIP(ip) {
			rs.ips[ip] = struct{}{}
		}
	}
	return rs, nil
}

// isIP reports whether s looks like a dotted-decimal IPv4 address.
// We accept any non-empty string that contains only digits and dots and has 3
// dots (4 octets) — cheap structural check, no strict range validation needed
// since these come from abuse.ch's curated CSV.
func isIP(s string) bool {
	if s == "" {
		return false
	}
	dots := 0
	for _, c := range s {
		if c == '.' {
			dots++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dots == 3
}

var urlRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>)\]}\x00-\x1f]+`)

// Check extracts URLs from data (and a defanged copy), and reports any whose
// host is a raw IP address listed in the Feodo blocklist. maxURLs bounds work.
func (c *Checker) Check(data []byte, maxURLs int) []Hit {
	c.lookups.Add(1)
	rs := c.rs.Load()
	if rs == nil || len(rs.ips) == 0 {
		return nil
	}
	if maxURLs <= 0 {
		maxURLs = 64
	}

	var out []Hit
	seen := make(map[string]struct{})
	check := func(text []byte, deobf bool, budget *int) {
		for _, m := range urlRe.FindAll(text, *budget) {
			if *budget <= 0 {
				return
			}
			*budget--
			norm, ip := extractIP(string(m))
			if ip == "" {
				continue
			}
			if _, dup := seen[norm]; dup {
				continue
			}
			seen[norm] = struct{}{}
			if _, ok := rs.ips[ip]; ok {
				out = append(out, Hit{URL: norm, IP: ip, Deobf: deobf})
			}
		}
	}

	budget := maxURLs
	check(data, false, &budget)
	if defanged := defang(data); defanged != "" {
		check([]byte(defanged), true, &budget)
	}
	if len(out) > 0 {
		c.hits.Add(1)
	}
	return out
}

// extractIP returns the (normalized URL, bare IP) if the URL's host is a raw
// IPv4 address, otherwise ("", "").
func extractIP(raw string) (norm, ip string) {
	raw = strings.TrimRight(strings.TrimSpace(raw), ".,);]}'\"")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", ""
	}
	h := u.Hostname()
	if !isIP(h) {
		return "", ""
	}
	hostPort := h
	if p := u.Port(); p != "" && !defaultPort(u.Scheme, p) {
		hostPort = h + ":" + p
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	norm = u.Scheme + "://" + hostPort + path
	if u.RawQuery != "" {
		norm += "?" + u.RawQuery
	}
	return norm, h
}

func defaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

func defang(data []byte) string {
	if !bytes.ContainsAny(data, "[({xX") {
		return ""
	}
	s := string(data)
	r := strings.NewReplacer(
		"hxxps", "https", "hXXps", "https", "hxxp", "http", "hXXp", "http",
		"[.]", ".", "(.)", ".", "{.}", ".",
		"[dot]", ".", "(dot)", ".", "{dot}", ".", "[DOT]", ".", " dot ", ".",
		"[:]", ":", "[://]", "://",
	)
	out := r.Replace(s)
	if out == s {
		return ""
	}
	return out
}

// Metrics returns a snapshot for /metrics.
func (c *Checker) Metrics() Metrics {
	rs := c.rs.Load()
	var n int
	if rs != nil {
		n = len(rs.ips)
	}
	return Metrics{
		Enabled:         true,
		FeedIPs:         int64(n),
		LastRefreshUnix: c.lastRefresh.Load(),
		RefreshFailures: c.failures.Load(),
		Lookups:         c.lookups.Load(),
		Hits:            c.hits.Load(),
	}
}
