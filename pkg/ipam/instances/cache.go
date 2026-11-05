// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package instances provides the instance cache shared by the cloud provider
// IPAM implementations.
package instances

import (
	"context"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// PublishFunc publishes provider state to the cache. It runs while the cache
// write lock is held, in the same critical section that publishes the
// instances fetched by the surrounding resync.
type PublishFunc func()

// FullResyncFunc fetches all instances from the cloud API. It runs while the
// full resync lock is held exclusively. The returned PublishFunc, if non-nil,
// publishes provider state fetched alongside the instances; it runs under the
// cache write lock together with the swap of the instance map.
type FullResyncFunc func(ctx context.Context) (*ipamTypes.InstanceMap, PublishFunc, error)

// InstanceSyncFunc fetches a single instance from the cloud API. It runs
// while the full resync lock is held shared, so that concurrent instance
// syncs proceed in parallel but never overlap a full resync. The returned
// PublishFunc, if non-nil, runs under the cache write lock together with the
// update of the instance.
type InstanceSyncFunc func(ctx context.Context) (*ipamTypes.Instance, PublishFunc, error)

// InstanceCache caches the instances and interfaces of a cloud provider and
// owns the locking scheme shared by the cloud provider IPAM implementations:
//
//   - resyncLock keeps incremental instance syncs and cache updates out of a
//     full API resync, so that an update made from state fetched before a full
//     resync started cannot overwrite the just-fetched state, and a full
//     resync that fetched before an update cannot overwrite that update.
//   - instanceLocks serializes incremental syncs and cache updates per
//     instance, so that an incremental sync whose fetch is delayed cannot
//     overwrite a newer concurrent update to the same instance.
//   - mutex protects the instance map, along with any provider state that is
//     resynced together with it. Providers access such state through Read,
//     Publish and the resync PublishFuncs.
//
// The lock order is always resyncLock before mutex. Neither lock is held
// while a cloud API is called: resyncs hold only resyncLock during the fetch
// and take mutex just to publish the result.
type InstanceCache struct {
	// resyncLock ensures that full API resyncs are mutually exclusive with
	// incremental instance syncs and cache updates.
	resyncLock    lock.RWMutex
	instanceLocks lock.KeyedMutex[string]

	// mutex protects instances and any provider state published through
	// Publish or a PublishFunc.
	mutex     lock.RWMutex
	instances *ipamTypes.InstanceMap
}

// NewInstanceCache returns a new empty instance cache.
func NewInstanceCache() *InstanceCache {
	return &InstanceCache{
		instances: ipamTypes.NewInstanceMap(),
	}
}

// NewInstanceCacheFrom returns a new instance cache primed with the given
// instance map, which must not be used by the caller afterwards. It is mainly
// useful in tests.
func NewInstanceCacheFrom(instances *ipamTypes.InstanceMap) *InstanceCache {
	return &InstanceCache{
		instances: instances,
	}
}

// FullResync fetches all instances via fetch and replaces the cached instance
// map with the result. It returns the time when the resync started, or an
// error if it did not complete.
func (c *InstanceCache) FullResync(ctx context.Context, fetch FullResyncFunc) (time.Time, error) {
	// A full API resync blocks the incremental instance syncs and cache
	// updates from all nodes.
	c.resyncLock.Lock()
	defer c.resyncLock.Unlock()

	resyncStart := time.Now()

	instances, publish, err := fetch(ctx)
	if err != nil {
		return time.Time{}, err
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.instances = instances
	if publish != nil {
		publish()
	}

	return resyncStart, nil
}

// InstanceSync fetches the given instance via fetch and updates it in the
// cached instance map. It returns the time when the sync started, or an error
// if it did not complete.
func (c *InstanceCache) InstanceSync(ctx context.Context, instanceID string, fetch InstanceSyncFunc) (time.Time, error) {
	unlock := c.lockInstance(instanceID)
	defer unlock()

	resyncStart := time.Now()

	instance, publish, err := fetch(ctx)
	if err != nil {
		return time.Time{}, err
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.instances.UpdateInstance(instanceID, instance)
	if publish != nil {
		publish()
	}

	return resyncStart, nil
}

func (c *InstanceCache) lockInstance(instanceID string) lock.UnlockFunc {
	unlockInstance := c.instanceLocks.Lock(instanceID)
	// The read lock allows incremental resyncs and cache updates for different
	// instances to run in parallel, while excluding full API resyncs, which take
	// the write lock.
	c.resyncLock.RLock()

	return func() {
		c.resyncLock.RUnlock()
		unlockInstance()
	}
}

// UpdateInstance applies fn to the cached instance map as an incremental
// cache update of the given instance. It blocks while a full resync or
// another operation on the same instance is in progress, so an update made
// from state fetched before either started cannot overwrite the just-fetched
// state.
func (c *InstanceCache) UpdateInstance(instanceID string, fn func(instances *ipamTypes.InstanceMap)) {
	unlock := c.lockInstance(instanceID)
	defer unlock()

	c.mutex.Lock()
	defer c.mutex.Unlock()
	fn(c.instances)
}

// UpdateInterface updates the interface definition of an instance as an
// incremental cache update. If the interface is already known, the definition
// is updated, otherwise it is added to the instance. Like UpdateInstance, it
// blocks while a full resync or another operation on the same instance is in
// progress.
func (c *InstanceCache) UpdateInterface(instanceID string, iface ipamTypes.Interface) {
	unlock := c.lockInstance(instanceID)
	defer unlock()

	c.mutex.Lock()
	defer c.mutex.Unlock()
	// Don't recreate a partial instance that was deleted while this update waited.
	if !c.instances.Exists(instanceID) {
		return
	}
	c.instances.Update(instanceID, iface)
}

// Read runs fn while holding the cache read lock. fn must not mutate the
// instance map; the lock also covers provider state published through Publish
// or a PublishFunc, so fn may read such state.
func (c *InstanceCache) Read(fn func(instances *ipamTypes.InstanceMap)) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	fn(c.instances)
}

// Publish runs fn while holding the cache write lock, to publish provider
// state that is read under the same lock via Read. Unlike Update it does not
// take the resync lock: the caller must already hold it, which is the case
// inside a FullResyncFunc or InstanceSyncFunc.
func (c *InstanceCache) Publish(fn func()) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	fn()
}

// HasInstance returns whether the instance is in the cached instance map.
func (c *InstanceCache) HasInstance(instanceID string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.instances.Exists(instanceID)
}

// DeleteInstance deletes an instance from the cached instance map. Like
// UpdateInstance, it blocks while a full resync or another operation on the
// same instance is in progress, so that a resync that fetched the instance
// before its deletion cannot resurrect it.
func (c *InstanceCache) DeleteInstance(instanceID string) {
	unlock := c.lockInstance(instanceID)
	defer unlock()

	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.instances.Delete(instanceID)
}

// ForeachInstance iterates over each interface of the given instance and
// calls fn. The cache is read-locked for the entire execution.
func (c *InstanceCache) ForeachInstance(instanceID string, fn ipamTypes.InterfaceIterator) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	c.instances.ForeachInterface(instanceID, fn)
}
