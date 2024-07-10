// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	"fmt"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// Resources maps resource names to channels that are closed upon initial
// sync with k8s.
type Resources struct {
	CacheStatus CacheStatus

	lock.RWMutex
	// resourceChannels maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	resources map[string]<-chan struct{}
	// stopWait contains the result of cache.WaitForCacheSync
	stopWait map[string]bool

	// timeSinceLastEvent contains the time each resource last received an event.
	timeSinceLastEvent map[string]time.Time
}

func (r *Resources) getTimeOfLastEvent(resource string) (when time.Time, never bool) {
	r.RLock()
	defer r.RUnlock()
	t, ok := r.timeSinceLastEvent[resource]
	if !ok {
		return time.Time{}, true
	}
	return t, false
}

func (r *Resources) SetEventTimestamp(resource string) {
	now := time.Now()
	r.Lock()
	defer r.Unlock()
	if r.timeSinceLastEvent != nil {
		r.timeSinceLastEvent[resource] = now
	}
}

func (r *Resources) CancelWaitGroupToSyncResources(resourceName string) {
	r.Lock()
	delete(r.resources, resourceName)
	r.Unlock()
}

// BlockWaitGroupToSyncResources ensures that anything which waits on waitGroup
// waits until all objects of the specified resource stored in Kubernetes are
// received by the informer and processed by controller.
// Fatally exits if syncing these initial objects fails.
// If the given stop channel is closed, it does not fatal.
// Once the k8s caches are synced against k8s, k8sCacheSynced is also closed.
func (r *Resources) BlockWaitGroupToSyncResources(
	stop <-chan struct{},
	swg *lock.StoppableWaitGroup,
	hasSyncedFunc cache.InformerSynced,
	resourceName string,
) {
	// Log an error caches have already synchronized, as the caller is making this call too late
	// and the resource in question was missed in the initial cache sync.
	if r.CacheStatus.Synchronized() {
		log.WithField("kubernetesResource", resourceName).Errorf("BlockWaitGroupToSyncResources called after Caches have already synced")
		return
	}
	ch := make(chan struct{})
	r.Lock()
	if r.resources == nil {
		r.resources = make(map[string]<-chan struct{})
		r.stopWait = make(map[string]bool)
		r.timeSinceLastEvent = make(map[string]time.Time)
	}
	r.resources[resourceName] = ch
	r.Unlock()

	go func() {
		scopedLog := log.WithField("kubernetesResource", resourceName)
		scopedLog.Debug("waiting for cache to synchronize")
		if ok := cache.WaitForCacheSync(stop, hasSyncedFunc); !ok {
			select {
			case <-stop:
				// do not fatal if the channel was stopped
				scopedLog.Debug("canceled cache synchronization")
				r.Lock()
				// Since the wait for cache sync was canceled we
				// need to mark that stopWait was canceled and it
				// should not stop waiting for this resource to be
				// synchronized.
				r.stopWait[resourceName] = false
				r.Unlock()
			default:
				// Fatally exit it resource fails to sync
				scopedLog.Fatalf("failed to wait for cache to sync")
			}
		} else {
			scopedLog.Debug("cache synced")
			r.Lock()
			// Since the wait for cache sync was not canceled we need to
			// mark that stopWait not canceled and it should stop
			// waiting for this resource to be synchronized.
			r.stopWait[resourceName] = true
			r.Unlock()
		}
		if swg != nil {
			swg.Stop()
			swg.Wait()
		}
		close(ch)
	}()
}

// WaitForCacheSync waits for all K8s resources represented by
// resourceNames to have their K8s caches synchronized.
func (r *Resources) WaitForCacheSync(resourceNames ...string) {
	for _, resourceName := range resourceNames {
		r.RLock()
		c, ok := r.resources[resourceName]
		r.RUnlock()
		if !ok {
			continue
		}
		for {
			scopedLog := log.WithField("kubernetesResource", resourceName)
			<-c
			r.RLock()
			stopWait := r.stopWait[resourceName]
			r.RUnlock()
			if stopWait {
				scopedLog.Debug("stopped waiting for caches to be synced")
				break
			}
			scopedLog.Debug("original cache sync operation was aborted, waiting for caches to be synced with a new channel...")
			time.Sleep(syncedPollPeriod)
			r.RLock()
			c, ok = r.resources[resourceName]
			r.RUnlock()
			if !ok {
				break
			}
		}
	}
}

// poll period for underlying client-go wait for cache sync.
const syncedPollPeriod = 100 * time.Millisecond

// WaitForCacheSyncWithTimeout waits for K8s resources represented by resourceNames to be synced.
// For every resource type, if an event happens after starting the wait, the timeout will be pushed out
// to be the time of the last event plus the timeout duration.
func (r *Resources) WaitForCacheSyncWithTimeout(timeout time.Duration, resourceNames ...string) error {
	// Upon completion, release event map to reduce unnecessary memory usage.
	// SetEventTimestamp calls to nil event time map are no-op.
	// Running BlockWaitGroupToSyncResources will reinitialize the event map.
	defer func() {
		r.Lock()
		r.timeSinceLastEvent = nil
		r.Unlock()
	}()

	wg := &errgroup.Group{}
	for _, resource := range resourceNames {
		done := make(chan struct{})
		go func(resource string) {
			r.WaitForCacheSync(resource)
			close(done)
		}(resource)

		waitFn := func(resource string) func() error {
			return func() error {
				currTimeout := timeout + syncedPollPeriod // add buffer of the poll period.

				for {
					// Wait until after timeout ends or sync is completed.
					// If timeout is reached, check if an event occurred that would
					// have pushed back the timeout and wait for that amount of time.
					select {
					case now := <-inctimer.After(currTimeout):
						lastEvent, never := r.getTimeOfLastEvent(resource)
						if never {
							return fmt.Errorf("timed out after %s, never received event for resource %q", timeout, resource)
						}
						if now.After(lastEvent.Add(timeout)) {
							return fmt.Errorf("timed out after %s since receiving last event for resource %q", timeout, resource)
						}
						// We reset the timer to wait the timeout period minus the
						// time since the last event.
						currTimeout = timeout - time.Since(lastEvent)
						log.Debugf("resource %q received event %s ago, waiting for additional %s before timing out", resource, time.Since(lastEvent), currTimeout)
					case <-done:
						log.Debugf("resource %q cache has synced, stopping timeout watcher", resource)
						return nil
					}
				}
			}
		}(resource)

		wg.Go(waitFn)
	}

	return wg.Wait()
}
