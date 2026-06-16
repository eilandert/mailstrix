package yarad

import (
	"container/list"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache stores scan verdicts keyed by SHA256(body). A YARA verdict is a pure
// function of the scanned bytes and the rule set, so unlike gozer's collaborative
// verdicts there is nothing to invalidate per-message — entries only expire by
// TTL. On a rules reload the whole cache is dropped (Flush) since old verdicts
// were computed against the previous rule set.
type Cache interface {
	Get(key string) ([]Match, bool)
	Put(key string, matches []Match)
	Flush()
}

// noopCache is used when YARAD_CACHE_TTL=0 (caching disabled): every Get misses.
type noopCache struct{}

func (noopCache) Get(string) ([]Match, bool) { return nil, false }
func (noopCache) Put(string, []Match)        {}
func (noopCache) Flush()                     {}

// lruCache is the always-on in-process layer: a TTL'd LRU bounded to CacheSize
// entries. Concurrency is a single mutex — Get/Put are O(1) and hold it only for
// the map/list ops, never across a scan. Under load the lock is uncontended
// relative to scan cost.
type lruCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	ll    *list.List               // front = most recently used
	items map[string]*list.Element // key -> element
	redis *redisLayer              // optional shared L2 (nil when no YARAD_REDIS_URL)
}

type entry struct {
	key     string
	matches []Match
	expires time.Time
}

// NewCache builds the verdict cache from cfg. TTL<=0 returns a noop cache. When
// RedisURL is set, a shared L2 is attached; a Redis that fails at runtime is
// treated as a miss (fail-open to scanning), never an error to the caller.
func NewCache(cfg *Config, logf func(string, ...any)) Cache {
	if cfg.CacheTTL <= 0 {
		return noopCache{}
	}
	c := &lruCache{
		ttl:   cfg.CacheTTL,
		max:   cfg.CacheSize,
		ll:    list.New(),
		items: make(map[string]*list.Element, cfg.CacheSize),
	}
	if cfg.RedisURL != "" {
		if rl, err := newRedisLayer(cfg); err != nil {
			logf("WARNING redis cache disabled: %v", err)
		} else {
			c.redis = rl
			logf("redis verdict cache enabled (prefix=%s)", cfg.RedisPrefix)
		}
	}
	return c
}

func (c *lruCache) Get(key string) ([]Match, bool) {
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry)
		if time.Now().Before(e.expires) {
			c.ll.MoveToFront(el)
			m := e.matches
			c.mu.Unlock()
			return m, true
		}
		// expired — drop it and fall through to L2
		c.removeElement(el)
	}
	c.mu.Unlock()

	// L1 miss: try the shared Redis layer, and on a hit promote into L1.
	if c.redis != nil {
		if m, ok := c.redis.get(key); ok {
			c.Put(key, m)
			return m, true
		}
	}
	return nil, false
}

func (c *lruCache) Put(key string, matches []Match) {
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry)
		e.matches = matches
		e.expires = time.Now().Add(c.ttl)
		c.ll.MoveToFront(el)
		c.mu.Unlock()
	} else {
		el := c.ll.PushFront(&entry{key: key, matches: matches, expires: time.Now().Add(c.ttl)})
		c.items[key] = el
		for c.ll.Len() > c.max {
			c.removeElement(c.ll.Back())
		}
		c.mu.Unlock()
	}
	if c.redis != nil {
		c.redis.put(key, matches, c.ttl)
	}
}

// Flush clears L1 (called on a rules reload). L2 is left to TTL-expire on its
// own: other replicas may still be on the old rule set mid-rollout, and Redis
// keys are namespaced so a stale entry just expires within CacheTTL.
func (c *lruCache) Flush() {
	c.mu.Lock()
	c.ll.Init()
	c.items = make(map[string]*list.Element, c.max)
	c.mu.Unlock()
}

// removeElement must be called with the lock held.
func (c *lruCache) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(*entry).key)
}

// --- optional Redis L2 ---

type redisLayer struct {
	rdb    *redis.Client
	prefix string
}

func newRedisLayer(cfg *Config) (*redisLayer, error) {
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, err
	}
	return &redisLayer{rdb: redis.NewClient(opt), prefix: cfg.RedisPrefix}, nil
}

// get/put fail open: any Redis error is logged-as-miss, never surfaced. The
// budget is short so a slow/dead Redis cannot stall the hot path — a miss just
// means we scan.
func (r *redisLayer) get(key string) ([]Match, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	b, err := r.rdb.Get(ctx, r.prefix+key).Bytes()
	if err != nil {
		return nil, false
	}
	var m []Match
	if json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	return m, true
}

func (r *redisLayer) put(key string, matches []Match, ttl time.Duration) {
	b, err := json.Marshal(matches)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = r.rdb.Set(ctx, r.prefix+key, b, ttl).Err()
}
