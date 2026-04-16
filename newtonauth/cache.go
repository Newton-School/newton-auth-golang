package newtonauth

import (
	"container/list"
	"sync"
	"time"
)

type cacheEntry struct {
	key       string
	value     authCheckResponse
	cachedAt  time.Time
	approxLen int
}

type lruCache struct {
	maxBytes int
	size     int
	mu       sync.Mutex
	ll       *list.List
	entries  map[string]*list.Element
}

func newLRUCache(maxMB int) *lruCache {
	if maxMB < 0 {
		maxMB = 0
	}
	return &lruCache{
		maxBytes: maxMB * 1024 * 1024,
		ll:       list.New(),
		entries:  make(map[string]*list.Element),
	}
}

func (c *lruCache) get(key string) (*authCheckResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*cacheEntry)
	ttl := entry.value.ClientCacheTTLSeconds
	if ttl == 0 || (ttl > 0 && time.Since(entry.cachedAt) > time.Duration(ttl)*time.Second) {
		c.removeElement(elem)
		return nil, false
	}
	c.ll.MoveToBack(elem)
	value := entry.value
	return &value, true
}

func (c *lruCache) set(key string, value authCheckResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		entry := elem.Value.(*cacheEntry)
		c.size -= entry.approxLen
		entry.value = value
		entry.cachedAt = time.Now()
		entry.approxLen = approximateCacheEntrySize(key, value)
		c.size += entry.approxLen
		c.ll.MoveToBack(elem)
		c.evict()
		return
	}

	entry := &cacheEntry{
		key:       key,
		value:     value,
		cachedAt:  time.Now(),
		approxLen: approximateCacheEntrySize(key, value),
	}
	elem := c.ll.PushBack(entry)
	c.entries[key] = elem
	c.size += entry.approxLen
	c.evict()
}

func (c *lruCache) evict() {
	for c.maxBytes >= 0 && c.size > c.maxBytes && c.ll.Len() > 0 {
		c.removeElement(c.ll.Front())
	}
}

func (c *lruCache) removeElement(elem *list.Element) {
	entry := elem.Value.(*cacheEntry)
	delete(c.entries, entry.key)
	c.ll.Remove(elem)
	c.size -= entry.approxLen
}

func approximateCacheEntrySize(key string, value authCheckResponse) int {
	return 128 + len(key) + len(value.UID) + 64
}
