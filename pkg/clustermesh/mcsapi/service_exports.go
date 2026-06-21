// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"maps"
	"slices"

	"k8s.io/apimachinery/pkg/types"

	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
)

type (
	ServiceExportsByNamespace map[string]ServiceExportsByName
	ServiceExportsByName      map[string]ServiceExportsByCluster
	ServiceExportsByCluster   map[string]*mcsapitypes.MCSAPIServiceSpec
)

type globalServiceExportCache struct {
	mutex lock.RWMutex
	cache ServiceExportsByNamespace

	// size is used to manage a counter of globalServiceExport
	// as uint instead of the float of metric.Gauge as float are not reliable to count
	size uint64
}

func newGlobalServiceExportCache() *globalServiceExportCache {
	return &globalServiceExportCache{
		cache: ServiceExportsByNamespace{},
	}
}

// GetServiceExportsName returns all the service exports for a specific namespace
// that have at least one service export in one of the remote cluster in the mesh.
func (c *globalServiceExportCache) GetServiceExportsName(namespace string) []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return slices.Collect(maps.Keys(c.cache[namespace]))
}

// GetServiceExportByCluster returns a shallow copy of the GlobalServiceExport
// object, thus the MCSAPIServiceSpec objects should not be mutated.
func (c *globalServiceExportCache) GetServiceExportByCluster(serviceExportNN types.NamespacedName) ServiceExportsByCluster {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	svcExportsByName, ok := c.cache[serviceExportNN.Namespace]
	if !ok {
		return nil
	}
	svcExportsByCluster, ok := svcExportsByName[serviceExportNN.Name]
	if !ok {
		return nil
	}
	return maps.Clone(svcExportsByCluster)
}

func (c *globalServiceExportCache) OnUpdate(svcExport *mcsapitypes.MCSAPIServiceSpec) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	svcExportsByName, ok := c.cache[svcExport.Namespace]
	if !ok {
		svcExportsByName = ServiceExportsByName{}
		c.cache[svcExport.Namespace] = svcExportsByName
	}
	svcExportsByCluster, ok := svcExportsByName[svcExport.Name]
	if !ok {
		svcExportsByCluster = ServiceExportsByCluster{}
		svcExportsByName[svcExport.Name] = svcExportsByCluster
		c.size += 1
	}

	svcExportsByCluster[svcExport.Cluster] = svcExport
}

func (c *globalServiceExportCache) OnDelete(svcExport *mcsapitypes.MCSAPIServiceSpec) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	svcExportsByName, ok := c.cache[svcExport.Namespace]
	if !ok {
		return false
	}
	svcExportsByCluster, ok := svcExportsByName[svcExport.Name]
	if !ok {
		return false
	}

	_, ok = svcExportsByCluster[svcExport.Cluster]
	if !ok {
		return false
	}
	delete(svcExportsByCluster, svcExport.Cluster)

	// cleanup the maps and update the size
	if len(svcExportsByName[svcExport.Name]) != 0 {
		return true
	}
	c.size -= 1
	delete(svcExportsByName, svcExport.Name)

	if len(c.cache[svcExport.Namespace]) != 0 {
		return true
	}
	delete(c.cache, svcExport.Namespace)

	return true
}

func (c *globalServiceExportCache) Size() uint64 {
	return c.size
}

type remoteServiceExportObserver struct {
	cache *globalServiceExportCache

	onUpdate func(*mcsapitypes.MCSAPIServiceSpec)
	onDelete func(*mcsapitypes.MCSAPIServiceSpec)
}

// newServiceExportsObserver returns an observer implementing the logic to convert
// and filter export notifications, update the global service export cache and
// call the upstream handlers when appropriate.
func newServiceExportsObserver(
	cache *globalServiceExportCache, onUpdate, onDelete func(*mcsapitypes.MCSAPIServiceSpec),
) store.Observer {
	return &remoteServiceExportObserver{
		cache: cache,

		onUpdate: onUpdate,
		onDelete: onDelete,
	}
}

// OnUpdate is called when a service export in a remote cluster is updated
func (r *remoteServiceExportObserver) OnUpdate(key store.Key) {
	svcExport := &(key.(*mcsapitypes.ValidatingMCSAPIServiceSpec).MCSAPIServiceSpec)
	r.cache.OnUpdate(svcExport)
	r.onUpdate(svcExport)
}

// OnDelete is called when a service export in a remote cluster is deleted
func (r *remoteServiceExportObserver) OnDelete(key store.NamedKey) {
	svcExport := &(key.(*mcsapitypes.ValidatingMCSAPIServiceSpec).MCSAPIServiceSpec)
	r.cache.OnDelete(svcExport)
	r.onDelete(svcExport)
}
