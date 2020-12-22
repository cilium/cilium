// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package synced

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"

	"k8s.io/client-go/tools/cache"
)

// Resources maps resource names to channels that are closed upon initial
// sync with k8s.
type Resources struct {
	lock.RWMutex
	// resourceChannels maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	resources map[string]<-chan struct{}
	// stopWait contains the result of cache.WaitForCacheSync
	stopWait map[string]bool
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
	ch := make(chan struct{})
	r.Lock()
	if r.resources == nil {
		r.resources = make(map[string]<-chan struct{})
		r.stopWait = make(map[string]bool)
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
			time.Sleep(100 * time.Millisecond)
			r.RLock()
			c, ok = r.resources[resourceName]
			r.RUnlock()
			if !ok {
				break
			}
		}
	}
}
