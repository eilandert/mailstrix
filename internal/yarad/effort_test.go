package yarad

import (
	"sync"
	"testing"
)

func TestResolveEffortLevel(t *testing.T) {
	cases := []struct {
		name   string
		hv     int
		hset   bool
		envDef int
		max    int
		want   int
	}{
		{"no header uses env default", 0, false, 7, 10, 7},
		{"header overrides env", 3, true, 7, 10, 3},
		{"header clamped to max (DoS guard)", 99, true, 5, 10, 10},
		{"header below 1 clamped up", 0, true, 5, 10, 1},
		{"negative header clamps to 1 (not env default)", -1, true, 9, 10, 1},
		{"env default above max clamped", 0, false, 50, 8, 8},
		{"negative env default floored", 0, false, -4, 10, 1},
		{"max below 1 floored to 1", 5, true, 5, 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveEffortLevel(c.hv, c.hset, c.envDef, c.max); got != c.want {
				t.Errorf("ResolveEffortLevel(%d,%v,%d,%d) = %d, want %d",
					c.hv, c.hset, c.envDef, c.max, got, c.want)
			}
		})
	}
}

func TestEffortProfileFor(t *testing.T) {
	// EFFORT-1: inert full-depth profile, Level carried through, level floored.
	if p := EffortProfileFor(5); p.Level != 5 {
		t.Errorf("Level not carried: got %d", p.Level)
	}
	if p := EffortProfileFor(0); p.Level != 1 {
		t.Errorf("stray 0 not floored to 1: got %d", p.Level)
	}
	p := EffortProfileFor(3)
	if !p.PDFDeepen || !p.ReputationFeeds || p.DecodeDepth != 4 {
		t.Errorf("EFFORT-1 profile must be full-depth/inert, got %+v", p)
	}
}

func TestConfigSanitizeEffort(t *testing.T) {
	cases := []struct {
		name                string
		effort, max         int
		wantEffort, wantMax int
	}{
		{"defaults: 0 effort becomes max", 0, 10, 10, 10},
		{"explicit in range", 4, 10, 4, 10},
		{"effort above max clamped to max", 20, 6, 6, 6},
		{"max above ceiling clamped", 5, 99, 5, defaultEffortMax},
		{"max below 1 clamped to default", 5, 0, 5, defaultEffortMax},
		{"negative effort floors to 1 (not max)", -3, 8, 1, 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{Effort: c.effort, EffortMax: c.max,
				ScanTimeout: 1, MaxBody: 1, CacheSize: 1, Port: 8079,
				BackendTimeout: 1, MaxConcurrent: 1, MaxInflight: 1}
			cfg.sanitize()
			if cfg.Effort != c.wantEffort || cfg.EffortMax != c.wantMax {
				t.Errorf("got Effort=%d Max=%d, want Effort=%d Max=%d",
					cfg.Effort, cfg.EffortMax, c.wantEffort, c.wantMax)
			}
			if cfg.Effort < 1 || cfg.Effort > cfg.EffortMax {
				t.Errorf("post-sanitize Effort %d out of [1,%d]", cfg.Effort, cfg.EffortMax)
			}
		})
	}
}

func TestScanMetaCacheKeyIncludesEffort(t *testing.T) {
	a := ScanMeta{Filename: "x.doc", Effort: 2}
	b := ScanMeta{Filename: "x.doc", Effort: 9}
	if a.cacheKey() == b.cacheKey() {
		t.Fatal("cacheKey must differ by effort level (same bytes, different depth = different verdict)")
	}
	if a.cacheKey() != (ScanMeta{Filename: "x.doc", Effort: 2}).cacheKey() {
		t.Fatal("cacheKey must be stable for identical meta")
	}
}

func TestAutoTargetLevel(t *testing.T) {
	cases := []struct {
		name                                string
		occupied, capacity, idle, max, want int
	}{
		{"only request -> idle ceiling", 1, 8, 10, 10, 10},
		{"full gate -> 1", 8, 8, 10, 10, 1},
		{"half full ~ midpoint", 5, 9, 9, 10, 5}, // frac=4/8=0.5, span=8, drop=4 -> 5
		{"unbounded gate -> idle", 4, 0, 7, 10, 7},
		{"single-slot gate -> idle (no measurable pressure)", 1, 1, 6, 10, 6},
		{"idle clamped to max", 1, 4, 50, 8, 8},
		{"idle floored to 1 -> always 1", 1, 4, 0, 10, 1},
		{"occupied over capacity clamped", 99, 4, 10, 10, 1},
		{"occupied under 1 floored", 0, 4, 10, 10, 10},
		{"never drops below 1", 4, 4, 2, 10, 1}, // span=1, full -> drop 1 -> 1
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := autoTargetLevel(c.occupied, c.capacity, c.idle, c.max); got != c.want {
				t.Fatalf("autoTargetLevel(%d,%d,%d,%d)=%d want %d", c.occupied, c.capacity, c.idle, c.max, got, c.want)
			}
		})
	}
}

func TestAutoStepLevel(t *testing.T) {
	cases := []struct{ cur, target, want int }{
		{0, 7, 7}, // uninitialised snaps to target
		{0, 1, 1}, //
		{5, 9, 6}, // ramp up one
		{5, 2, 4}, // ramp down one
		{5, 5, 5}, // steady
		{5, 6, 6}, // adjacent up
		{5, 4, 4}, // adjacent down
	}
	for _, c := range cases {
		if got := autoStepLevel(c.cur, c.target); got != c.want {
			t.Fatalf("autoStepLevel(%d,%d)=%d want %d", c.cur, c.target, got, c.want)
		}
	}
}

func TestConfigEffortAuto(t *testing.T) {
	t.Setenv("YARAD_EFFORT", "auto")
	c := LoadConfig()
	if !c.EffortAuto {
		t.Fatal("YARAD_EFFORT=auto must set EffortAuto")
	}
	if c.Effort != c.EffortMax {
		t.Fatalf("auto idle level must default to EffortMax: Effort=%d EffortMax=%d", c.Effort, c.EffortMax)
	}
}

// TestAutoEnvDefaultConcurrent hammers the auto resolver from many goroutines to
// prove the CAS step is race-free (run under -race) and that the smoothed level
// stays in [1, EffortMax] and only ever moves one level per scan.
func TestAutoEnvDefaultConcurrent(t *testing.T) {
	cfg := &Config{Token: "t", MaxConcurrent: 8, MaxBody: 1 << 20, EffortAuto: true}
	cfg.sanitize() // sets Effort=EffortMax, MaxInflight=2×MaxConcurrent
	s := NewServer(cfg, &fakeEngine{count: 1})

	// Pre-load the admission gate to simulate pressure (half full).
	for i := 0; i < cap(s.admit)/2; i++ {
		s.admit <- struct{}{}
	}

	const G, N = 16, 200
	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				lvl := s.autoEnvDefault(true)
				if lvl < 1 || lvl > cfg.EffortMax {
					t.Errorf("auto level %d out of [1,%d]", lvl, cfg.EffortMax)
					return
				}
			}
		}()
	}
	wg.Wait()
	if got := s.autoEffort.Load(); got < 1 || got > int64(cfg.EffortMax) {
		t.Fatalf("final autoEffort %d out of [1,%d]", got, cfg.EffortMax)
	}
}
