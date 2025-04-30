// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"log/slog"
	"maps"

	"k8s.io/apimachinery/pkg/types"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type GlobalService struct {
	ClusterServices map[string]*serviceStore.ClusterService
}

func newGlobalService() *GlobalService {
	return &GlobalService{
		ClusterServices: map[string]*serviceStore.ClusterService{},
	}
}

type GlobalServiceCache struct {
	logger *slog.Logger
	mutex  lock.RWMutex
	byName map[types.NamespacedName]*GlobalService

	// metricTotalGlobalServices is the gauge metric for total of global services
	metricTotalGlobalServices metric.Gauge
}

func NewGlobalServiceCache(logger *slog.Logger, metricTotalGlobalServices metric.Gauge) *GlobalServiceCache {
	return &GlobalServiceCache{
		logger:                    logger,
		byName:                    map[types.NamespacedName]*GlobalService{},
		metricTotalGlobalServices: metricTotalGlobalServices,
	}
}

// Has returns whether a given service is present in the cache.
func (c *GlobalServiceCache) Has(svc *serviceStore.ClusterService) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if globalSvc, ok := c.byName[svc.NamespaceServiceName()]; ok {
		_, ok = globalSvc.ClusterServices[svc.Cluster]
		return ok
	}

	return false
}

// GetService returns the service for a specific cluster. This function does not
// make a copy of the cluster service object and should not be mutated.
func (c *GlobalServiceCache) GetService(serviceNN types.NamespacedName, clusterName string) *serviceStore.ClusterService {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if globalSvc, ok := c.byName[serviceNN]; ok {
		if svc, ok := globalSvc.ClusterServices[clusterName]; ok {
			return svc
		}
	}

	return nil
}

// GetGlobalService returns a global service object. This function returns
// a shallow copy of the GlobalService object, thus the ClusterService objects
// should not be mutated.
func (c *GlobalServiceCache) GetGlobalService(serviceNN types.NamespacedName) *GlobalService {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if globalSvc, ok := c.byName[serviceNN]; ok {
		// We copy the global service to make this thread safe
		newGlobalSvc := newGlobalService()
		newGlobalSvc.ClusterServices = maps.Clone(globalSvc.ClusterServices)
		return newGlobalSvc
	}

	return nil
}

func (c *GlobalServiceCache) OnUpdate(svc *serviceStore.ClusterService) {
	c.mutex.Lock()

	// Validate that the global service is known
	globalSvc, ok := c.byName[svc.NamespaceServiceName()]
	if !ok {
		globalSvc = newGlobalService()
		c.byName[svc.NamespaceServiceName()] = globalSvc
		c.logger.Debug(
			"Created new global service",
			logfields.ServiceName, svc,
			logfields.ClusterName, svc.Cluster,
		)
		c.metricTotalGlobalServices.Set(float64(len(c.byName)))
	}

	c.logger.Debug(
		"Updated service definition of remote cluster",
		logfields.ServiceName, svc,
		logfields.ClusterName, svc.Cluster,
	)

	globalSvc.ClusterServices[svc.Cluster] = svc
	c.mutex.Unlock()
}

// must be called with c.mutex held
func (c *GlobalServiceCache) delete(globalService *GlobalService, clusterName string, serviceNN types.NamespacedName) bool {
	if _, ok := globalService.ClusterServices[clusterName]; !ok {
		c.logger.Debug("Ignoring delete request for unknown cluster",
			logfields.ServiceName, serviceNN,
			logfields.ClusterName, clusterName,
		)
		return false
	}

	c.logger.Debug("Deleted service definition of remote cluster",
		logfields.ServiceName, serviceNN,
		logfields.ClusterName, clusterName,
	)
	delete(globalService.ClusterServices, clusterName)

	// After the last cluster service is removed, remove the global service
	if len(globalService.ClusterServices) == 0 {
		c.logger.Debug("Deleted global service",
			logfields.ServiceName, serviceNN,
			logfields.ClusterName, clusterName,
		)
		delete(c.byName, serviceNN)
		c.metricTotalGlobalServices.Set(float64(len(c.byName)))
	}

	return true
}

func (c *GlobalServiceCache) OnDelete(svc *serviceStore.ClusterService) bool {
	c.logger.Debug("Delete event for service", logfields.ServiceName, svc)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if globalService, ok := c.byName[svc.NamespaceServiceName()]; ok {
		return c.delete(globalService, svc.Cluster, svc.NamespaceServiceName())
	} else {
		c.logger.Debug("Ignoring delete request for unknown global service", logfields.ServiceName, svc)
		return false
	}
}

// Size returns the number of global services in the cache
func (c *GlobalServiceCache) Size() (num int) {
	c.mutex.RLock()
	num = len(c.byName)
	c.mutex.RUnlock()
	return
}

type remoteServiceObserver struct {
	log *slog.Logger

	cache *GlobalServiceCache

	onUpdate func(*serviceStore.ClusterService)
	onDelete func(*serviceStore.ClusterService)
}

// NewSharedServicesObserver returns an observer implementing the logic to convert
// and filter shared services notifications, update the global service cache and
// call the upstream handlers when appropriate.
func NewSharedServicesObserver(
	log *slog.Logger, cache *GlobalServiceCache,
	onUpdate, onDelete func(*serviceStore.ClusterService),
) store.Observer {
	return &remoteServiceObserver{
		log:   log,
		cache: cache,

		onUpdate: onUpdate,
		onDelete: onDelete,
	}
}

// OnUpdate is called when a service in a remote cluster is updated
func (r *remoteServiceObserver) OnUpdate(key store.Key) {
	svc := &(key.(*serviceStore.ValidatingClusterService).ClusterService)
	r.log.Debug("Received remote service update event", logfields.ServiceName, svc)

	// Short-circuit the handling of non-shared services
	if !svc.Shared {
		if r.cache.Has(svc) {
			r.log.Debug("Previously shared service is no longer shared: triggering deletion event", logfields.ServiceName, svc)
			r.OnDelete(key)
		} else {
			r.log.Debug("Ignoring remote service update: service is not shared", logfields.ServiceName, svc)
		}
		return
	}

	r.cache.OnUpdate(svc)
	r.onUpdate(svc)
}

// OnDelete is called when a service in a remote cluster is deleted
func (r *remoteServiceObserver) OnDelete(key store.NamedKey) {
	svc := &(key.(*serviceStore.ValidatingClusterService).ClusterService)
	r.log.Debug("Received remote service delete event", logfields.ServiceName, svc)

	// Short-circuit the deletion logic if the service was not present (i.e., not shared)
	if !r.cache.OnDelete(svc) {
		r.log.Debug("Ignoring remote service delete. Service was not shared", logfields.ServiceName, svc)
		return
	}

	r.onDelete(svc)
}
