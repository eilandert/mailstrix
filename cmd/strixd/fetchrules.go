package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// defaultRulesURL is the rolling release directory that generate-rules.sh
// publishes compiled.yac + its manifest to. Override with -url / MAILSTRIX_RULES_URL
// (e.g. to point at a mirror).
const defaultRulesURL = "https://github.com/myguard-labs/mailstrix/releases/download/rules-current"

// cmdFetchRules downloads an updated compiled rule bundle into the cache, driven
// by the published manifest: it fetches the manifest first and updates only when
// the remote version is newer and the libyara version matches. It verifies the
// download (sha256) and swaps atomically, keeping one backup. It is the
// counterpart to generate-rules.sh and the primary rule-update path for both
// Docker and non-Docker users (no local yarac / compile).
//
// Exit codes: 0 = up to date or updated successfully; 2 = error (kept the current
// bundle). A `serve`-time interval fetch reuses internal/mailstrix.FetchRules.
func cmdFetchRules(args []string) int {
	cfg := mailstrix.LoadConfig()

	fs := flag.NewFlagSet("fetch-rules", flag.ContinueOnError)
	url := fs.String("url", envOr("MAILSTRIX_RULES_URL", defaultRulesURL), "base URL holding compiled.yac + its manifest (MAILSTRIX_RULES_URL)")
	cacheDir := fs.String("cache-dir", firstNonEmpty(cfg.CacheDir, "/var/cache/mailstrix"), "cache dir for the live bundle (MAILSTRIX_CACHE_DIR)")
	timeout := fs.Duration("timeout", 60*time.Second, "overall HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	// Redirects ARE followed (a GitHub release-asset URL legitimately 30x's to the
	// object store, so a blanket reject would break the default URL), but the chain
	// is bounded. These requests carry NO auth/secret header — the bundle is a
	// public asset — so there is nothing for a redirect to leak; the only guard
	// needed is a hop cap against a redirect loop.
	hc := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	res, err := mailstrix.FetchRules(ctx, *url, *cacheDir, libyaraVersion, hc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strixd fetch-rules:", err)
		return 2
	}
	if res.Updated {
		fmt.Printf("fetch-rules: %s — restart or SIGHUP strixd to load the new bundle\n", res.Reason)
	} else {
		fmt.Printf("fetch-rules: %s\n", res.Reason)
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
