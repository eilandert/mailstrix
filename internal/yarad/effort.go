package yarad

// Effort tiers (EFFORT-1) — the operator/caller cost dial.
//
// A single scalar level (1..EffortMax) scales every bounded extraction/scan cap
// so one binary serves a latency-tight front (rspamd, pre-queue) and a deeper
// backend (LDA/sieve), and can shed work under load. Level 1 = raw bytes plus
// the shallowest structural extraction; EffortMax = every decoder/feed at full
// depth.
//
// This file defines the CONTRACT only (EFFORT-1):
//   - EffortProfile: the resolved per-request cap set;
//   - ResolveEffortLevel: header/env resolution with the DoS clamp;
//   - EffortProfileFor: level -> profile.
//
// The profile is threaded to the scanner and folded into the verdict-cache key,
// but the individual caps (MSD decode depth, XLM/PDF clamps, reputation-feed
// gating, scan timeout) still read their package constants today. EFFORT-4
// retrofits each cap to read its EffortProfile field. Until then every level
// resolves to the same effective behaviour (full depth) — the plumbing is
// present but inert, so each new feature wires its cap in from day one and the
// dial activates the moment EFFORT-4 lands.

// EffortProfile is the resolved set of caps for one scan's effort level. Fields
// are the dials EFFORT-4 will wire; today they are populated for observability /
// cache-key stability but not yet read by the extractors.
type EffortProfile struct {
	// Level is the resolved effort (1..EffortMax) this profile was built for. It
	// is what folds into the verdict-cache key, so two scans of the same bytes at
	// different effort can hold distinct verdicts.
	Level int

	// DecodeDepth caps the MSD multi-layer static-decode recursion (decode.go
	// maxDecodeDepth). PDFDeepen enables the PDF action/JS indicator pass
	// (pdf.go fromPDFIndicators). ReputationFeeds enables the URLhaus/MalwareBazaar
	// lookups. These are the first caps EFFORT-4 wires; more (XLM formula/sheet
	// caps, fold/carve clamps, maxStreams) follow.
	DecodeDepth     int
	PDFDeepen       bool
	ReputationFeeds bool
}

// EffortProfileFor maps an effort level to its profile. EFFORT-1 returns a
// full-depth profile at every level (the inert contract): the structure and the
// Level field are real, the cap VALUES are the current always-on behaviour so no
// scan changes until EFFORT-4 introduces per-level differentiation.
//
// level is assumed already resolved/clamped to [1, EffortMax] by
// ResolveEffortLevel; it is defensively floored at 1 here so a stray 0 can't
// produce a degenerate profile.
func EffortProfileFor(level int) EffortProfile {
	if level < 1 {
		level = 1
	}
	// Inert full-depth profile (EFFORT-1). EFFORT-4 replaces the constants below
	// with a level-indexed table.
	return EffortProfile{
		Level:           level,
		DecodeDepth:     4, // mirrors extract.maxDecodeDepth (current always-on value)
		PDFDeepen:       true,
		ReputationFeeds: true,
	}
}

// autoTargetLevel maps current admission-gate pressure to the effort level the
// auto resolver (EFFORT-2) wants to be at. It is the steady-state target; the
// stepper (autoStepLevel) approaches it one level per scan for hysteresis.
//
//	occupied  in-flight admission slots (including the caller's own held slot),
//	          so it is in [1, capacity].
//	capacity  the gate size (cfg.MaxInflight); a non-positive value means the gate
//	          is effectively unbounded, so there is no pressure -> idle level.
//	idleLevel the ceiling to use when the gate is empty (cfg.Effort, == EffortMax
//	          by default). The target never exceeds it.
//	effortMax the operator's hard ceiling; idleLevel is clamped into [1, effortMax].
//
// Mapping: empty gate -> idleLevel; full gate -> 1; linear in between. We measure
// pressure as the fraction of slots used BEYOND the caller's own (occupied-1 over
// capacity-1) so a single in-flight request (no contention) still maps to the
// idle ceiling, and a saturated gate maps to 1.
func autoTargetLevel(occupied, capacity, idleLevel, effortMax int) int {
	if effortMax < 1 {
		effortMax = 1
	}
	if idleLevel < 1 {
		idleLevel = 1
	}
	if idleLevel > effortMax {
		idleLevel = effortMax
	}
	// No bound (or a degenerate 1-slot gate) -> no measurable pressure.
	if capacity <= 1 {
		return idleLevel
	}
	if occupied < 1 {
		occupied = 1
	}
	if occupied > capacity {
		occupied = capacity
	}
	// Fraction of contention in [0,1]: 0 when we are the only request, 1 when the
	// gate is full. span = idleLevel-1 levels to give away under full pressure.
	span := idleLevel - 1
	if span <= 0 {
		return idleLevel
	}
	// drop = round(frac * span), frac = (occupied-1)/(capacity-1).
	num := (occupied - 1) * span
	den := capacity - 1
	drop := (num + den/2) / den // integer round-half-up
	level := idleLevel - drop
	if level < 1 {
		level = 1
	}
	return level
}

// autoStepLevel moves the smoothed auto level one step toward target. Stepping
// by at most one level per scan is the hysteresis: a brief pressure spike can't
// slam effort to 1 and back, it ramps. cur==0 (uninitialised) snaps straight to
// target so the first scan starts at the right level, not at 0+1.
func autoStepLevel(cur, target int) int {
	if cur < 1 {
		return target // first observation: adopt target directly
	}
	switch {
	case target > cur:
		return cur + 1
	case target < cur:
		return cur - 1
	default:
		return cur
	}
}

// ResolveEffortLevel applies the request-time resolution order:
//
//	header (if a valid 1..N int was sent) ?? envDefault
//
// then clamps the result to [1, effortMax]. The clamp is the DoS guard: a caller
// (or an attacker who can set the X-YARAD-Effort header) can never drive effort
// above the operator's configured ceiling. A malformed/empty header falls back
// to the env default; a header below 1 or above effortMax is clamped, not
// rejected (fail-toward-configured, never error a scan over a header).
//
// headerSet reports whether the header carried a usable integer (so the caller
// can distinguish "no header" from "header == envDefault" for metrics if wanted).
func ResolveEffortLevel(headerVal int, headerSet bool, envDefault, effortMax int) int {
	level := envDefault
	if headerSet {
		level = headerVal
	}
	if effortMax < 1 {
		effortMax = 1
	}
	if level < 1 {
		level = 1
	}
	if level > effortMax {
		level = effortMax
	}
	return level
}
