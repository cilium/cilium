// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"maps"
	"slices"

	"k8s.io/apimachinery/pkg/types"

	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type (
	ServiceExportsByNamespace map[string]ServiceExportsByName
	ServiceExportsByName      map[string]ServiceExportsByCluster
	ServiceExportsByCluster   map[string]*mcsapitypes.MCSAPIServiceSpec
)

type GlobalServiceExportCache struct {
	mutex lock.RWMutex
	cache ServiceExportsByNamespace

	// size is used to manage a counter of globalServiceExport
	// as uint instead of the float of metric.Gauge as float are not reliable to count
	size uint64
	// metricTotalGlobalServiceExports is the gauge metric for total of global service exports
	metricTotalGlobalServiceExports metric.Gauge
}

func NewGlobalServiceExportCache(metricTotalGlobalServiceExports metric.Gauge) *GlobalServiceExportCache {
	return &GlobalServiceExportCache{
		cache:                           ServiceExportsByNamespace{},
		metricTotalGlobalServiceExports: metricTotalGlobalServiceExports,
	}
}

// GetServiceExportsName returns all the service exports for a specific namespace
// that have at least one service export in one of the remote cluster in the mesh.
func (c *GlobalServiceExportCache) GetServiceExportsName(namespace string) []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return slices.Collect(maps.Keys(c.cache[namespace]))
}

// GetServiceExportByCluster returns a shallow copy of the GlobalServiceExport
// object, thus the MCSAPIServiceSpec objects should not be mutated.
func (c *GlobalServiceExportCache) GetServiceExportByCluster(serviceExportNN types.NamespacedName) ServiceExportsByCluster {
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

func (c *GlobalServiceExportCache) OnUpdate(svcExport *mcsapitypes.MCSAPIServiceSpec) {
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
		c.metricTotalGlobalServiceExports.Set(float64(c.size))
	}

	svcExportsByCluster[svcExport.Cluster] = svcExport
}

func (c *GlobalServiceExportCache) OnDelete(svcExport *mcsapitypes.MCSAPIServiceSpec) bool {
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
	c.metricTotalGlobalServiceExports.Set(float64(c.size))
	delete(svcExportsByName, svcExport.Name)

	if len(c.cache[svcExport.Namespace]) != 0 {
		return true
	}
	delete(c.cache, svcExport.Namespace)

	return true
}

func (c *GlobalServiceExportCache) Size() uint64 {
	return c.size
}

type remoteServiceExportObserver struct {
	cache *GlobalServiceExportCache

	onUpdate func(*mcsapitypes.MCSAPIServiceSpec)
	onDelete func(*mcsapitypes.MCSAPIServiceSpec)
}

// NewServiceExportsObserver returns an observer implementing the logic to convert
// and filter export notifications, update the global service export cache and
// call the upstream handlers when appropriate.
func NewServiceExportsObserver(
	cache *GlobalServiceExportCache, onUpdate, onDelete func(*mcsapitypes.MCSAPIServiceSpec),
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
	r.onDelete(svcExport)
}
