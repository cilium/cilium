package hybrid

import "github.com/cilium/cilium/pkg/lock"

type cidEventTracker struct {
	cidCreatedMap map[string]bool
	mu            lock.RWMutex
}

func newCIDEventTracker() *cidEventTracker {
	return &cidEventTracker{
		cidCreatedMap: make(map[string]bool),
	}
}

func (c *cidEventTracker) add(cidName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cidCreatedMap[cidName] = true
}

func (c *cidEventTracker) remove(cidName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cidCreatedMap, cidName)
}

func (c *cidEventTracker) isTracked(cidName string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.cidCreatedMap[cidName]
	return exists
}
