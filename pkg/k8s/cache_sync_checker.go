// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

type CacheSyncedChecker struct {
	c chan struct{}
}

func NewCacheSyncedChecker() *CacheSyncedChecker {
	return &CacheSyncedChecker{
		c: make(chan struct{}),
	}
}

// Wait blocks until the kubernetes cache has been synced
func (sc *CacheSyncedChecker) Wait() {
	<-sc.c
}

func (sc *CacheSyncedChecker) IsSynced() bool {
	select {
	case <-sc.c:
		return true
	default:
		return false
	}
}

func (sc *CacheSyncedChecker) Synced() {
	close(sc.c)
}
