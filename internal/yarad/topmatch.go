package yarad

import (
	"sort"
	"sync"
)

// matchCounterCap is the maximum number of distinct rule names tracked.
// When a 1025th unique rule arrives the lowest-count entry is evicted.
const matchCounterCap = 1024

// matchCounter tracks per-rule hit counts in a bounded map. It is safe for
// concurrent use. The map is bounded to matchCounterCap entries; when it
// grows beyond that the lowest-count entry is evicted (O(n) scan, but eviction
// is rare — only on the 1025th, 2026th, … unique rule name).
type matchCounter struct {
	mu     sync.Mutex
	counts map[string]uint64
	max    int
}

func newMatchCounter(max int) *matchCounter {
	return &matchCounter{counts: make(map[string]uint64), max: max}
}

// Add increments the counter for each rule name in rules.
func (c *matchCounter) Add(rules []string) {
	if len(rules) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range rules {
		c.counts[r]++
	}
	if len(c.counts) > c.max {
		c.evict()
	}
}

// evict removes the lowest-count entry when the map exceeds max.
// Simple O(n) scan — called rarely (only when cap exceeded).
func (c *matchCounter) evict() {
	minK, minV := "", uint64(^uint64(0))
	for k, v := range c.counts {
		if v < minV {
			minK, minV = k, v
		}
	}
	delete(c.counts, minK)
}

// MatchCount is one entry in the top-matches list.
type MatchCount struct {
	Rule  string `json:"rule"`
	Count uint64 `json:"count"`
}

// TopN returns up to n rules with the highest hit counts, sorted descending.
func (c *matchCounter) TopN(n int) []MatchCount {
	c.mu.Lock()
	snap := make(map[string]uint64, len(c.counts))
	for k, v := range c.counts {
		snap[k] = v
	}
	c.mu.Unlock()

	all := make([]MatchCount, 0, len(snap))
	for k, v := range snap {
		all = append(all, MatchCount{Rule: k, Count: v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// Reset clears all counters (called after a successful rule reload).
func (c *matchCounter) Reset() {
	c.mu.Lock()
	c.counts = make(map[string]uint64)
	c.mu.Unlock()
}
