// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"log/slog"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Cache is a key-value container which allows atomically updating entries and
// incrementing a version number if the cache is actually modified.
// Cache implements the ResourceSet interface.
// This cache implementation ignores the proxy node identifiers, i.e. the same
// resources are available under the same names to all nodes.
type Cache struct {
	logger *slog.Logger
	locker lock.RWMutex

	// versionCh is closed whenever version is increased and then replaced with a
	// fresh open channel for future waiters.
	versionCh chan struct{}

	// resources is the map of cached resource name to resource entry.
	resources map[cacheKey]cacheValue

	// version is the current version of the resources in the cache.
	// valid version numbers start at 1, which is the version of a cache
	// before any modifications have been made
	version uint64
}

// cacheKey uniquely identifies a resource.
type cacheKey struct {
	// typeURL is the URL that uniquely identifies the resource's type.
	typeURL string

	// resourceName is the name of the resource, unique among all the resources
	// of this type.
	resourceName string
}

// cacheValue is a cached resource.
type cacheValue struct {
	// resource is the resource in this cache entry.
	resource proto.Message

	// lastModifiedVersion is the version when this resource entry was last
	// modified.
	lastModifiedVersion uint64
}

// NewCache creates a new, empty cache with 1 as its current version.
func NewCache(logger *slog.Logger) *Cache {
	return &Cache{
		logger:    logger,
		versionCh: make(chan struct{}),
		resources: make(map[cacheKey]cacheValue),
		version:   1,
	}
}

func (c *Cache) advanceVersionLocked(version uint64) bool {
	if version < c.version {
		logging.Fatal(c.logger,
			"decreasing version number found for resources: newVersion < xdsCachedVersion",
			logfields.NewVersion, version,
			logfields.XDSCachedVersion, c.version,
		)
	}
	if version == c.version {
		return false
	}

	oldVersionCh := c.versionCh
	c.version = version
	c.versionCh = make(chan struct{})
	close(oldVersionCh)
	return true
}

// TX inserts/updates a set of resources, then deletes a set of resources, then
// increases the cache's version number atomically if the cache is actually
// changed.
// The version after updating the set is returned.
func (c *Cache) TX(typeURL string, upsertedResources map[string]proto.Message, deletedNames []string) (version uint64, updated bool, revert ResourceMutatorRevertFunc) {
	c.locker.Lock()
	defer c.locker.Unlock()

	cacheIsUpdated := false
	newVersion := c.version + 1

	scopedLog := c.logger.With(
		logfields.XDSTypeURL, typeURL,
		logfields.XDSCachedVersion, newVersion,
	)

	scopedLog.Debug(
		"preparing new cache transaction",
		logfields.Upserted, len(upsertedResources),
		logfields.Deleted, len(deletedNames),
	)

	// The parameters to pass to tx in revertFunc.
	var revertUpsertedResources map[string]proto.Message
	var revertDeletedNames []string

	k := cacheKey{
		typeURL: typeURL,
	}

	v := cacheValue{
		lastModifiedVersion: newVersion,
	}

	for name, value := range upsertedResources {
		k.resourceName = name
		oldV, found := c.resources[k]
		// If the value is unchanged, don't update the entry, to preserve its
		// lastModifiedVersion. This allows minimizing the frequency of
		// responses in GetResources.
		if !found || !proto.Equal(oldV.resource, value) {
			if found {
				scopedLog.Debug(
					"updating resource in cache",
					logfields.XDSResourceName, name,
				)

				if revertUpsertedResources == nil {
					revertUpsertedResources = make(map[string]proto.Message, len(upsertedResources)+len(deletedNames))
				}
				revertUpsertedResources[name] = oldV.resource
			} else {
				scopedLog.Debug(
					"inserting resource into cache",
					logfields.XDSResourceName, name,
				)

				if revertDeletedNames == nil {
					revertDeletedNames = make([]string, 0, len(upsertedResources))
				}
				revertDeletedNames = append(revertDeletedNames, name)
			}
			cacheIsUpdated = true
			v.resource = value
			c.resources[k] = v
		}
	}

	for _, name := range deletedNames {
		k.resourceName = name
		oldV, found := c.resources[k]
		if found {
			scopedLog.Debug(
				"deleting resource from cache",
				logfields.XDSResourceName, name,
			)

			if revertUpsertedResources == nil {
				revertUpsertedResources = make(map[string]proto.Message, len(upsertedResources)+len(deletedNames))
			}
			revertUpsertedResources[name] = oldV.resource

			cacheIsUpdated = true
			delete(c.resources, k)
		}
	}

	if cacheIsUpdated {
		scopedLog.Debug(
			"committing cache transaction with new version",
		)
		c.advanceVersionLocked(newVersion)

		revert = func() (version uint64, updated bool) {
			version, updated, _ = c.TX(typeURL, revertUpsertedResources, revertDeletedNames)
			return
		}
	} else {
		scopedLog.Debug(
			"cache unmodified by transaction; aborting",
		)
	}

	return c.version, cacheIsUpdated, revert
}

func (c *Cache) Upsert(typeURL string, resourceName string, resource proto.Message) (version uint64, updated bool, revert ResourceMutatorRevertFunc) {
	return c.TX(typeURL, map[string]proto.Message{resourceName: resource}, nil)
}

func (c *Cache) Delete(typeURL string, resourceName string) (version uint64, updated bool, revert ResourceMutatorRevertFunc) {
	return c.TX(typeURL, nil, []string{resourceName})
}

func (c *Cache) Clear(typeURL string) (version uint64, updated bool) {
	c.locker.Lock()
	defer c.locker.Unlock()

	cacheIsUpdated := false
	newVersion := c.version + 1

	scopedLog := c.logger.With(
		logfields.XDSTypeURL, typeURL,
		logfields.XDSCachedVersion, newVersion,
	)

	scopedLog.Debug("preparing new cache transaction: deleting all entries")

	for k := range c.resources {
		if k.typeURL == typeURL {
			scopedLog.Debug(
				"deleting resource from cache",
				logfields.XDSResourceName, k.resourceName,
			)
			cacheIsUpdated = true
			delete(c.resources, k)
		}
	}

	if cacheIsUpdated {
		scopedLog.Debug("committing cache transaction with new version")
		c.advanceVersionLocked(newVersion)
	} else {
		scopedLog.Debug("cache unmodified by transaction; aborting")
	}

	return c.version, cacheIsUpdated
}

func (c *Cache) HasAny(typeURL string) bool {
	c.locker.Lock()
	defer c.locker.Unlock()

	for k := range c.resources {
		if typeURL == AnyTypeURL || k.typeURL == typeURL {
			return true
		}
	}
	return false
}

func compareVersionedResource(a, b VersionedResource) int {
	if a.Name < b.Name {
		return -1
	}
	if a.Name > b.Name {
		return 1
	}
	return 0
}

func (c *Cache) GetResources(typeURL string, lastVersion uint64, resourceNames []string) *VersionedResources {
	c.locker.RLock()
	defer c.locker.RUnlock()

	scopedLog := c.logger.With(
		logfields.XDSAckedVersion, lastVersion,
		logfields.XDSTypeURL, typeURL,
	)

	if lastVersion > 0 && c.version <= lastVersion {
		// nothing has changed in the cache
		return nil
	}

	res := &VersionedResources{
		Version: c.version,
		Canary:  false,
	}

	// Return all resources of given typeURL.
	if len(resourceNames) == 0 {
		res.VersionedResources = make([]VersionedResource, 0, len(c.resources))
		for k, v := range c.resources {
			if k.typeURL != typeURL {
				continue
			}
			res.appendResource(k.resourceName, v.lastModifiedVersion, v.resource)
		}
		scopedLog.Debug(
			"no resource names requested",
			logfields.Resources, len(res.VersionedResources),
		)
		return res
	}

	// Return only the resources with the requested names.

	// As an optimization, if all the requested resources are found but none of
	// them has been modified since the lastVersion, return no response.
	// If at least one resource is not found, return all the found resources
	// anyway, because we don't know whether the missing resource was deleted
	// after the lastVersion, so we can't optimize in this case.

	res.VersionedResources = make([]VersionedResource, 0, len(resourceNames))

	k := cacheKey{typeURL: typeURL}

	allResourcesFound := true
	updatedSinceLastVersion := false

	scopedLog.Debug(
		"resource names requested, filtering resources",
		logfields.Resources, len(resourceNames),
	)

	for _, name := range resourceNames {
		k.resourceName = name
		v, found := c.resources[k]
		if found {
			scopedLog.Debug(
				"resource found, last modified in version",
				logfields.LastModifiedVersion, v.lastModifiedVersion,
				logfields.XDSResourceName, name,
			)
			if lastVersion == 0 || (lastVersion < v.lastModifiedVersion) {
				updatedSinceLastVersion = true
			}
			res.appendResource(name, v.lastModifiedVersion, v.resource)
		} else {
			scopedLog.Debug(
				"resource not found",
				logfields.XDSResourceName, name,
			)
			allResourcesFound = false
		}
	}
	if allResourcesFound && !updatedSinceLastVersion {
		scopedLog.Debug("all requested resources found but not updated since last version, returning no response")
		return nil
	}

	slices.SortFunc(res.VersionedResources, compareVersionedResource)

	scopedLog.Debug(
		"returning resources",
		logfields.ReturningResources, len(res.VersionedResources),
		logfields.RequestedResources, len(resourceNames),
	)
	return res
}

func (c *Cache) VersionState() (version uint64, changed <-chan struct{}) {
	c.locker.RLock()
	defer c.locker.RUnlock()

	return c.version, c.versionCh
}

func (c *Cache) GetDeltaResources(typeURL string, lastAckedVersion uint64, subscriptions set.Set[string], ackedResourceNames set.Set[string], forceResponseNames set.Set[string], forceEmptyResponse bool) *VersionedResources {
	c.locker.RLock()
	defer c.locker.RUnlock()

	scopedLog := c.logger.With(
		logfields.XDSAckedVersion, lastAckedVersion,
		logfields.XDSTypeURL, typeURL,
	)

	res := &VersionedResources{
		Version: c.version,
		Canary:  false,
	}

	key := cacheKey{typeURL: typeURL}
	wildcard := subscriptions.Empty() || subscriptions.Has("*")

	appendIfNeeded := func(name string, v cacheValue) {
		if v.lastModifiedVersion > lastAckedVersion ||
			forceResponseNames.Has(name) || forceResponseNames.Has("*") {
			res.appendResource(name, v.lastModifiedVersion, v.resource)
		}
	}

	if wildcard {
		for k, v := range c.resources {
			if k.typeURL != typeURL {
				continue
			}
			appendIfNeeded(k.resourceName, v)
		}
	} else {
		for name := range subscriptions.Members() {
			key.resourceName = name
			v, found := c.resources[key]
			if !found {
				continue
			}
			appendIfNeeded(name, v)
		}
	}

	// record removed resources if previously acknowledged and still subscribed
	for name := range ackedResourceNames.Members() {
		if wildcard || subscriptions.Has(name) {
			key.resourceName = name
			if _, exists := c.resources[key]; !exists {
				res.RemovedNames = append(res.RemovedNames, name)
			}
		}
	}

	if len(res.VersionedResources) == 0 && len(res.RemovedNames) == 0 && !forceEmptyResponse {
		scopedLog.Debug("Delta xDS: no changes")
		return nil
	}

	if len(res.VersionedResources) > 1 {
		slices.SortFunc(res.VersionedResources, compareVersionedResource)
	}

	if len(res.RemovedNames) > 1 {
		slices.Sort(res.RemovedNames)
	}

	scopedLog.Debug(
		"returning delta resources",
		logfields.ReturningResources, len(res.VersionedResources),
		logfields.Removed, len(res.RemovedNames),
	)

	return res
}

func (c *Cache) EnsureVersion(typeURL string, version uint64) {
	c.locker.Lock()
	defer c.locker.Unlock()

	if c.version < version {
		c.logger.Debug(
			"increasing version to match client",
			logfields.XDSTypeURL, typeURL,
			logfields.XDSAckedVersion, version,
		)

		// bump the lastUpdatedVersion of each resource of this typeURL
		for k, v := range c.resources {
			if k.typeURL != typeURL {
				continue
			}
			// use the forced version for each resource to force full update
			c.resources[k] = cacheValue{
				resource:            v.resource,
				lastModifiedVersion: version,
			}
		}

		c.advanceVersionLocked(version)
	}
}

// Lookup finds the resource corresponding to the specified typeURL and resourceName,
// if available, and returns it. Otherwise, returns nil.
func (c *Cache) Lookup(typeURL string, resourceName string) proto.Message {
	res := c.GetResources(typeURL, 0, []string{resourceName})
	if res == nil || len(res.VersionedResources) == 0 {
		return nil
	}
	return res.VersionedResources[0].Resource
}
