// Package threatfox adds an abuse.ch ThreatFox IOC lookup to yarad: URLs and
// domains pulled from a message (and from the decompressed VBA/RTF the extract
// package surfaces) are checked against a locally-cached feed of recent
// malicious indicators.
//
// Design mirrors internal/urlhaus (same Auth-Key, same fetch/refresh/cache
// pattern):
//   - The IOC CSV is downloaded once per refresh interval (>=5 min fair-use).
//   - A failed refresh keeps the previous set (fail-static).
//   - URL and domain IOCs are stored in separate sets; a hit on either is
//     reported with an appropriate rule name.
//   - Cheap defanging catches obfuscated URLs (hxxp / [.] / (dot)).
//   - Per-message URL count is bounded by maxURLs.
//
// ThreatFox focuses on botnet C&C indicators (post-infection), complementing
// URLhaus's delivery-URL focus. The same abuse.ch Auth-Key (free account at
// https://auth.abuse.ch/) works for both services. When no key is supplied,
// New returns nil (feature disabled).
package threatfox

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
	// feedURL is the ThreatFox recent-IOCs CSV dump (last 7 days).
	feedURL = "https://threatfox-api.abuse.ch/export/csv/recent/"

	minRefresh     = 5 * time.Minute
	defaultRefresh = 360 * time.Minute
	fetchTimeout   = 60 * time.Second
	maxFeedBytes   = 64 << 20 // hard ceiling on a downloaded feed
)

// Hit is one URL or domain in a scanned buffer that matched the ThreatFox feed.
type Hit struct {
	URL   string // matched (normalized) URL or domain
	Host  bool   // matched at host/domain level rather than exact URL
	Deobf bool   // found only after defanging — more suspicious
}

// Rule returns the synthetic rule name for a hit.
func (h Hit) Rule() string {
	name := "THREATFOX_IOC_URL"
	if h.Host {
		name = "THREATFOX_IOC_DOMAIN"
	}
	if h.Deobf {
		name += "_DEOBF"
	}
	return name
}

// Metrics is a snapshot for /metrics.
type Metrics struct {
	Enabled         bool
	FeedURLs        int64
	FeedDomains     int64
	LastRefreshUnix int64
	RefreshFailures uint64
	Lookups         uint64
	Hits            uint64
}

type ruleset struct {
	urls    map[string]struct{}
	domains map[string]struct{}
}

// Checker holds the cached feed and serves lookups.
type Checker struct {
	rs        atomic.Pointer[ruleset]
	key       string
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

// New builds a Checker and starts its background refresher. Returns nil when
// key is empty (feature disabled). refresh is clamped to the fair-use floor.
func New(key string, refresh time.Duration, cacheDir string, logf func(string, ...any)) *Checker {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	if refresh <= 0 {
		refresh = defaultRefresh
	}
	if refresh < minRefresh {
		refresh = minRefresh
	}
	c := &Checker{
		key:     key,
		refresh: refresh,
		stop:    make(chan struct{}),
		client:  &http.Client{Timeout: fetchTimeout},
		logf:    logf,
	}
	if cacheDir != "" {
		c.cachePath = filepath.Join(cacheDir, "threatfox.csv")
	}
	c.rs.Store(&ruleset{urls: map[string]struct{}{}, domains: map[string]struct{}{}})
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
		c.logf("threatfox warm-start parse failed (ignoring cached feed): %v", err)
		return
	}
	c.rs.Store(rs)
	c.logf("threatfox warm-start from cache: %d urls / %d domains", len(rs.urls), len(rs.domains))
}

func (c *Checker) refreshLoop() {
	if err := c.refreshOnce(); err != nil {
		c.failures.Add(1)
		c.logf("threatfox initial feed fetch failed: %v", err)
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
				c.logf("threatfox feed refresh failed (keeping previous set): %v", err)
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
	req.Header.Set("Auth-Key", c.key)
	req.Header.Set("Accept", "text/csv")
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
			c.logf("threatfox feed cache write failed (non-fatal): %v", err)
		}
	}
	c.logf("threatfox feed loaded: %d urls / %d domains", len(rs.urls), len(rs.domains))
	return nil
}

type statusError struct{ code int }

func (e *statusError) Error() string { return "threatfox feed HTTP " + strconv.Itoa(e.code) }

// parseFeed reads the ThreatFox CSV.
// Format: # id,ioc_type,ioc_value,...  (comment lines start with #)
// We extract rows where ioc_type is "url" or "domain".
func parseFeed(r io.Reader) (*ruleset, error) {
	rs := &ruleset{urls: make(map[string]struct{}), domains: make(map[string]struct{})}
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
		// Expect: id, ioc_type, ioc_value, ...
		if len(rec) < 3 {
			continue
		}
		iocType := strings.ToLower(strings.TrimSpace(rec[1]))
		iocValue := strings.TrimSpace(rec[2])
		switch iocType {
		case "url":
			norm, host := normalizeURL(iocValue)
			if norm != "" {
				rs.urls[norm] = struct{}{}
				if host != "" {
					rs.domains[host] = struct{}{}
				}
			}
		case "domain":
			if d := strings.ToLower(iocValue); d != "" {
				rs.domains[d] = struct{}{}
			}
		}
	}
	return rs, nil
}

var urlRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>)\]}\x00-\x1f]+`)

// Check extracts URLs from data (and from a cheaply-defanged copy), looks each
// up in the feed, and returns the matches. maxURLs bounds work per buffer.
func (c *Checker) Check(data []byte, maxURLs int) []Hit {
	c.lookups.Add(1)
	rs := c.rs.Load()
	if rs == nil || (len(rs.urls) == 0 && len(rs.domains) == 0) {
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
			norm, host := normalizeURL(string(m))
			if norm == "" {
				continue
			}
			if _, dup := seen[norm]; dup {
				continue
			}
			seen[norm] = struct{}{}
			if _, ok := rs.urls[norm]; ok {
				out = append(out, Hit{URL: norm, Deobf: deobf})
			} else if host != "" {
				if _, ok := rs.domains[host]; ok {
					out = append(out, Hit{URL: host, Host: true, Deobf: deobf})
				}
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

func normalizeURL(raw string) (norm, host string) {
	raw = strings.TrimRight(strings.TrimSpace(raw), ".,);]}'\"")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "" {
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

// Metrics returns a snapshot for /metrics.
func (c *Checker) Metrics() Metrics {
	rs := c.rs.Load()
	var nu, nd int
	if rs != nil {
		nu, nd = len(rs.urls), len(rs.domains)
	}
	return Metrics{
		Enabled:         true,
		FeedURLs:        int64(nu),
		FeedDomains:     int64(nd),
		LastRefreshUnix: c.lastRefresh.Load(),
		RefreshFailures: c.failures.Load(),
		Lookups:         c.lookups.Load(),
		Hits:            c.hits.Load(),
	}
}
