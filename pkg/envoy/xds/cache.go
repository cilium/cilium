// Copyright 2018 Authors of Cilium
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

package xds

import (
	"context"
	"sort"

	"github.com/cilium/cilium/pkg/logging/logfields"

	envoy_api_v2_core "github.com/cilium/proxy/go/envoy/api/v2/core"
	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
)

// Cache is a key-value container which allows atomically updating entries and
// incrementing a version number and notifying observers if the cache is actually
// modified.
// Cache implements the ObservableResourceSet interface.
// This cache implementation ignores the proxy node identifiers, i.e. the same
// resources are available under the same names to all nodes.
// Each cache contains resources of one type only.
type Cache struct {
	*BaseObservableResourceSource

	// typeURL is the type of resources in this cache
	typeURL string

	// resources is the map of cached resource name to resource entry.
	resources map[string]VersionedResource

	// version is the current version of the resources in the cache.
	// valid version numbers start at 1, which is the version of a cache
	// before any modifications have been made
	version uint64
}

// VersionedResource is a cached resource.
type VersionedResource struct {
	// Resource is the resource in this cache entry.
	Resource proto.Message

	// LastModifiedVersion is the version when this resource entry was last
	// modified.
	LastModifiedVersion uint64
}

// NewCache creates a new, empty cache with 0 as its current version.
func NewCache(typeURL string) *Cache {
	return &Cache{
		BaseObservableResourceSource: NewBaseObservableResourceSource(),
		typeURL:                      typeURL,
		resources:                    make(map[string]VersionedResource),
		version:                      1,
	}
}

func (c *Cache) Upsert(resourceName string, resource proto.Message, force bool) (version uint64, updated bool, revert ResourceMutatorRevertFunc) {
	c.locker.Lock()
	defer c.locker.Unlock()

	cacheIsUpdated := false
	newVersion := c.version + 1

	cacheLog := log.WithFields(logrus.Fields{
		logfields.XDSTypeURL:     c.typeURL,
		logfields.XDSVersionInfo: newVersion,
	})

	cacheLog.Debugf("preparing new cache transaction: upserting an entry")

	oldV, found := c.resources[resourceName]
	// If the value is unchanged, don't update the entry, to preserve its
	// LastModifiedVersion. This allows minimizing the frequency of
	// responses in GetResources.
	if !found || !proto.Equal(oldV.Resource, resource) {
		if found {
			cacheLog.WithField(logfields.XDSResourceName, resourceName).Debug("updating resource in cache")
		} else {
			cacheLog.WithField(logfields.XDSResourceName, resourceName).Debug("inserting resource into cache")
		}
		cacheIsUpdated = true
		c.resources[resourceName] = VersionedResource{
			LastModifiedVersion: newVersion,
			Resource:            resource,
		}
	} else {
		// no change, do not notify about this resource
	}

	if cacheIsUpdated || force {
		cacheLog.Debug("committing cache transaction and notifying of new version")
		c.version = newVersion
		c.NotifyNewResourceVersionRLocked(c.version)
	} else {
		cacheLog.Debug("cache unmodified by transaction; aborting")
	}

	revertFunc := func(force bool) (version uint64, updated bool) {
		version, updated = c.version, false
		if cacheIsUpdated {
			if found {
				// Add previous resource back
				version, updated, _ = c.Upsert(resourceName, oldV.Resource, force)
			} else {
				// Delete inserted resource
				version, updated, _ = c.Delete(resourceName, force)
			}
		}
		return
	}

	return c.version, cacheIsUpdated || force, revertFunc
}

func (c *Cache) Delete(resourceName string, force bool) (version uint64, updated bool, revert ResourceMutatorRevertFunc) {
	c.locker.Lock()
	defer c.locker.Unlock()

	newVersion := c.version + 1

	cacheLog := log.WithFields(logrus.Fields{
		logfields.XDSTypeURL:     c.typeURL,
		logfields.XDSVersionInfo: newVersion,
	})

	cacheLog.Debugf("preparing new cache transaction: deleting an entry")

	oldV, found := c.resources[resourceName]
	if found {
		cacheLog.WithField(logfields.XDSResourceName, resourceName).Debug("deleting resource from cache")
		delete(c.resources, resourceName)
	}

	if found || force {
		cacheLog.Debug("committing cache transaction and notifying of new version")
		c.version = newVersion
		c.NotifyNewResourceVersionRLocked(c.version)
	} else {
		cacheLog.Debug("cache unmodified by transaction; aborting")
	}

	revertFunc := func(force bool) (version uint64, updated bool) {
		version, updated = c.version, false
		if found {
			// Add previous resource back
			version, updated, _ = c.Upsert(resourceName, oldV.Resource, force)
		}
		return
	}

	return c.version, found || force, revertFunc
}

func (c *Cache) Clear(force bool) (version uint64, updated bool) {
	c.locker.Lock()
	defer c.locker.Unlock()

	cacheIsUpdated := force
	newVersion := c.version + 1

	cacheLog := log.WithFields(logrus.Fields{
		logfields.XDSTypeURL:     c.typeURL,
		logfields.XDSVersionInfo: newVersion,
	})

	cacheLog.Debug("preparing new cache transaction: deleting all entries")

	for name := range c.resources {
		cacheLog.WithField(logfields.XDSResourceName, name).
			Debug("deleting resource from cache")
		cacheIsUpdated = true
		delete(c.resources, name)
	}

	if cacheIsUpdated {
		cacheLog.Debug("committing cache transaction and notifying of new version")
		c.version = newVersion
		c.NotifyNewResourceVersionRLocked(c.version)
	} else {
		cacheLog.Debug("cache unmodified by transaction; aborting")
	}

	return c.version, cacheIsUpdated
}

func (c *Cache) GetResources(ctx context.Context, lastVersion uint64,
	node *envoy_api_v2_core.Node, resourceNames []string) (*VersionedResources, error) {
	c.locker.RLock()
	defer c.locker.RUnlock()

	cacheLog := log.WithFields(logrus.Fields{
		logfields.XDSVersionInfo: lastVersion,
		logfields.XDSClientNode:  node,
		logfields.XDSTypeURL:     c.typeURL,
	})

	res := &VersionedResources{
		Version: c.version,
	}

	// Return all resources.
	if len(resourceNames) == 0 {
		res.ResourceNames = make([]string, 0, len(c.resources))
		res.Resources = make([]VersionedResource, 0, len(c.resources))
		cacheLog.Debugf("no resource names requested, returning all %d resources", len(c.resources))
		for name, v := range c.resources {
			res.ResourceNames = append(res.ResourceNames, name)
			res.Resources = append(res.Resources, v)
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
	res.Resources = make([]VersionedResource, 0, len(resourceNames))

	allResourcesFound := true
	updatedSinceLastVersion := false

	cacheLog.Debugf("%d resource names requested, filtering resources", len(resourceNames))

	for _, name := range resourceNames {
		v, found := c.resources[name]
		if found {
			cacheLog.WithField(logfields.XDSResourceName, name).
				Debugf("resource found, last modified in version %d", v.LastModifiedVersion)
			if lastVersion == 0 || (lastVersion < v.LastModifiedVersion) {
				updatedSinceLastVersion = true
			}
			res.ResourceNames = append(res.ResourceNames, name)
			res.Resources = append(res.Resources, v)
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

func (c *Cache) EnsureVersion(version uint64) {
	c.locker.Lock()
	defer c.locker.Unlock()

	if c.version < version {
		cacheLog := log.WithFields(logrus.Fields{
			logfields.XDSTypeURL:     c.typeURL,
			logfields.XDSVersionInfo: version,
		})
		cacheLog.Debug("increasing version to match client and notifying of new version")

		c.version = version
		c.NotifyNewResourceVersionRLocked(c.version)
	}
}

// Lookup finds the resource corresponding to the specified resourceName,
// if available, and returns it. Otherwise, returns nil.
func (c *Cache) Lookup(resourceName string) proto.Message {
	c.locker.RLock()
	defer c.locker.RUnlock()

	return c.resources[resourceName].Resource
}
