package yarad

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	yara "github.com/hillu/go-yara/v4"
)

// cachedRulesName is the live compiled bundle's filename inside CacheDir.
const cachedRulesName = "compiled.yac"

// EnsureCachedRules implements the seed-on-startup / self-heal behaviour: when a
// writable CacheDir is configured, yarad serves its rules from
// CacheDir/compiled.yac, and that file is (re)seeded from the baked, read-only
// SeedRules whenever it is missing or unreadable. This makes a fresh deploy — or
// a wiped/cleared bindmount — always recover a known-good, image-tested ruleset
// with no network. A later step adds `--fetch-rules` to refresh the cache copy
// from a release.
//
// It mutates cfg.RulesPath to point at the cache file so the existing scanner
// load path is unchanged. When CacheDir is empty the function is a no-op (the old
// behaviour: load RulesPath/RulesDir directly).
//
// Seeding is best-effort but explicit: if the cache is empty and seeding fails
// (no seed, unwritable dir), it returns an error so the caller can fall back to
// the baked RulesPath rather than start with no rules.
func EnsureCachedRules(cfg *Config, logf func(string, ...any)) error {
	if cfg.CacheDir == "" {
		return nil // caching disabled — load RulesPath/RulesDir as before
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o750); err != nil {
		return fmt.Errorf("cache dir %s: %w", cfg.CacheDir, err)
	}
	cachePath := filepath.Join(cfg.CacheDir, cachedRulesName)

	// Trust the cache only if it is non-empty AND actually loads under this
	// libyara. A bundle that is the right shape but corrupt or compiled against a
	// different libyara passes rulesFileUsable yet crashes the scanner load at
	// startup/SIGHUP — by which point the known-good seed may be the only recovery.
	// Load-validate here so an unloadable cache is reseeded NOW, not discovered later.
	if rulesFileUsable(cachePath) {
		if err := rulesBundleLoadable(cachePath); err == nil {
			cfg.RulesPath = cachePath
			return nil
		} else {
			logf("WARNING: cached rules %s present but not loadable (%v); reseeding from baked seed", cachePath, err)
		}
	}

	// Cache missing, unreadable, or not loadable — reseed from the baked, read-only seed.
	seed := cfg.SeedRules
	if seed == "" {
		seed = cfg.RulesPath // fall back to whatever bundle the image baked
	}
	if !rulesFileUsable(seed) {
		return fmt.Errorf("cache %s is empty and no usable seed (YARAD_SEED_RULES/%s)", cachePath, cfg.RulesPath)
	}
	if err := rulesBundleLoadable(seed); err != nil {
		return fmt.Errorf("seed %s is not a loadable rule bundle: %w", seed, err)
	}
	if err := copyFileAtomic(seed, cachePath); err != nil {
		return fmt.Errorf("seed %s -> %s: %w", seed, cachePath, err)
	}
	logf("seeded rules cache %s from %s", cachePath, seed)
	cfg.RulesPath = cachePath
	return nil
}

// rulesFileUsable reports whether path is a non-empty, readable regular file.
func rulesFileUsable(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		return false
	}
	f, err := os.Open(path) // #nosec G304 -- operator-configured rules path
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// rulesBundleLoadable reports whether path is a compiled .yac that actually loads
// under the linked libyara — the only check that catches a corrupt or
// wrong-libyara bundle that nonetheless has the right size/shape/checksum. The
// loaded rules are destroyed immediately (this is a validation probe, not the live
// load). A nil return means the bundle is safe to trust/swap.
func rulesBundleLoadable(path string) error {
	r, err := yara.LoadRules(path)
	if err != nil {
		return err
	}
	if r != nil {
		r.Destroy() // free the C-side rules; we only needed to prove it loads
	}
	return nil
}

// copyFileAtomic copies src to dst by writing a temp file in dst's directory and
// renaming it into place (same-filesystem rename is atomic), so a concurrent
// reader never sees a half-written bundle. The temp file is cleaned up on error.
func copyFileAtomic(src, dst string) (err error) {
	in, err := os.Open(src) // #nosec G304 -- operator-configured seed path
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".compiled-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}
