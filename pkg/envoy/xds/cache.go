// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"sort"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Cache is a key-value container which allows atomically updating entries and
// incrementing a version number and notifying observers if the cache is actually
// modified.
// Cache implements the ObservableResourceSet interface.
// This cache implementation ignores the proxy node identifiers, i.e. the same
// resources are available under the same names to all nodes.
type Cache struct {
	*BaseObservableResourceSource

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

// NewCache creates a new, empty cache with 0 as its current version.
func NewCache() *Cache {
	return &Cache{
		BaseObservableResourceSource: NewBaseObservableResourceSource(),
		resources:                    make(map[cacheKey]cacheValue),
		version:                      1,
	}
}

// tx inserts/updates a set of resources, then deletes a set of resources, then
// increases the cache's version number atomically if the cache is actually
// changed.
// The version after updating the set is returned.
func (c *Cache) tx(typeURL string, upsertedResources map[string]proto.Message, deletedNames []string) (version uint64, updated bool, revert ResourceMutatorRevertFunc) {
	c.locker.Lock()
	defer c.locker.Unlock()

	cacheIsUpdated := false
	newVersion := c.version + 1

	cacheLog := log.WithFields(logrus.Fields{
		logfields.XDSTypeURL:       typeURL,
		logfields.XDSCachedVersion: newVersion,
	})

	cacheLog.Debugf("preparing new cache transaction: upserting %d entries, deleting %d entries",
		len(upsertedResources), len(deletedNames))

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
				cacheLog.WithField(logfields.XDSResourceName, name).Debug("updating resource in cache")

				if revertUpsertedResources == nil {
					revertUpsertedResources = make(map[string]proto.Message, len(upsertedResources)+len(deletedNames))
				}
				revertUpsertedResources[name] = oldV.resource
			} else {
				cacheLog.WithField(logfields.XDSResourceName, name).Debug("inserting resource into cache")

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
			cacheLog.WithField(logfields.XDSResourceName, name).
				Debug("deleting resource from cache")

			if revertUpsertedResources == nil {
				revertUpsertedResources = make(map[string]proto.Message, len(upsertedResources)+len(deletedNames))
			}
			revertUpsertedResources[name] = oldV.resource

			cacheIsUpdated = true
			delete(c.resources, k)
		}
	}

	if cacheIsUpdated {
		cacheLog.Debug("committing cache transaction and notifying of new version")
		c.version = newVersion
		c.NotifyNewResourceVersionRLocked(typeURL, c.version)

		revert = func() (version uint64, updated bool) {
			version, updated, _ = c.tx(typeURL, revertUpsertedResources, revertDeletedNames)
			return
		}
	} else {
		cacheLog.Debug("cache unmodified by transaction; aborting")
	}

	return c.version, cacheIsUpdated, revert
}

func (c *Cache) Upsert(typeURL string, resourceName string, resource proto.Message) (version uint64, updated bool, revert ResourceMutatorRevertFunc) {
	return c.tx(typeURL, map[string]proto.Message{resourceName: resource}, nil)
}

func (c *Cache) Delete(typeURL string, resourceName string) (version uint64, updated bool, revert ResourceMutatorRevertFunc) {
	return c.tx(typeURL, nil, []string{resourceName})
}

func (c *Cache) Clear(typeURL string) (version uint64, updated bool) {
	c.locker.Lock()
	defer c.locker.Unlock()

	cacheIsUpdated := false
	newVersion := c.version + 1

	cacheLog := log.WithFields(logrus.Fields{
		logfields.XDSTypeURL:       typeURL,
		logfields.XDSCachedVersion: newVersion,
	})

	cacheLog.Debug("preparing new cache transaction: deleting all entries")

	for k := range c.resources {
		if k.typeURL == typeURL {
			cacheLog.WithField(logfields.XDSResourceName, k.resourceName).
				Debug("deleting resource from cache")
			cacheIsUpdated = true
			delete(c.resources, k)
		}
	}

	if cacheIsUpdated {
		cacheLog.Debug("committing cache transaction and notifying of new version")
		c.version = newVersion
		c.NotifyNewResourceVersionRLocked(typeURL, c.version)
	} else {
		cacheLog.Debug("cache unmodified by transaction; aborting")
	}

	return c.version, cacheIsUpdated
}

func (c *Cache) GetResources(ctx context.Context, typeURL string, lastVersion uint64, nodeIP string, resourceNames []string) (*VersionedResources, error) {
	c.locker.RLock()
	defer c.locker.RUnlock()

	cacheLog := log.WithFields(logrus.Fields{
		logfields.XDSAckedVersion: lastVersion,
		logfields.XDSClientNode:   nodeIP,
		logfields.XDSTypeURL:      typeURL,
	})

	res := &VersionedResources{
		Version: c.version,
		Canary:  false,
	}

	// Return all resources.
	// TODO: return nil if no changes since the last version?
	if len(resourceNames) == 0 {
		res.ResourceNames = make([]string, 0, len(c.resources))
		res.Resources = make([]proto.Message, 0, len(c.resources))
		cacheLog.Debugf("no resource names requested, returning all %d resources", len(c.resources))
		for k, v := range c.resources {
			res.ResourceNames = append(res.ResourceNames, k.resourceName)
			res.Resources = append(res.Resources, v.resource)
		}
		return res, nil
	}

	// Return only the resources with the requested names.

	// As an optimization, if all the requested resources are found but none of
	// them has been modified since the lastVersion, return no response.
	// If at least one resource is not found, return all the found resources
	// anyway, because we don't know whether the missing resource was deleted
	// after the lastVersion, so we can't optimize in this case.

	res.ResourceNames = make([]string, 0, len(resourceNames))
	res.Resources = make([]proto.Message, 0, len(resourceNames))

	k := cacheKey{typeURL: typeURL}

	allResourcesFound := true
	updatedSinceLastVersion := false

	cacheLog.Debugf("%d resource names requested, filtering resources", len(resourceNames))

	for _, name := range resourceNames {
		k.resourceName = name
		v, found := c.resources[k]
		if found {
			cacheLog.WithField(logfields.XDSResourceName, name).
				Debugf("resource found, last modified in version %d", v.lastModifiedVersion)
			if lastVersion == 0 || (lastVersion < v.lastModifiedVersion) {
				updatedSinceLastVersion = true
			}
			res.ResourceNames = append(res.ResourceNames, name)
			res.Resources = append(res.Resources, v.resource)
		} else {
			cacheLog.WithField(logfields.XDSResourceName, name).Debug("resource not found")
			allResourcesFound = false
		}
	}

	if allResourcesFound && !updatedSinceLastVersion {
		cacheLog.Debug("all requested resources found but not updated since last version, returning no response")
		return nil, nil
	}

	sort.Strings(res.ResourceNames)

	cacheLog.Debugf("returning %d resources out of %d requested", len(res.Resources), len(resourceNames))
	return res, nil
}

func (c *Cache) EnsureVersion(typeURL string, version uint64) {
	c.locker.Lock()
	defer c.locker.Unlock()

	if c.version < version {
		cacheLog := log.WithFields(logrus.Fields{
			logfields.XDSTypeURL:      typeURL,
			logfields.XDSAckedVersion: version,
		})
		cacheLog.Debug("increasing version to match client and notifying of new version")

		c.version = version
		c.NotifyNewResourceVersionRLocked(typeURL, c.version)
	}
}

// Lookup finds the resource corresponding to the specified typeURL and resourceName,
// if available, and returns it. Otherwise, returns nil. If an error occurs while
// fetching the resource, also returns the error.
func (c *Cache) Lookup(typeURL string, resourceName string) (proto.Message, error) {
	res, err := c.GetResources(context.Background(), typeURL, 0, "", []string{resourceName})
	if err != nil || res == nil || len(res.Resources) == 0 {
		return nil, err
	}
	return res.Resources[0], nil
}
