// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"maps"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
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
	mutex  lock.RWMutex
	byName map[types.NamespacedName]*GlobalService

	// metricTotalGlobalServices is the gauge metric for total of global services
	metricTotalGlobalServices metric.Gauge
}

func NewGlobalServiceCache(metricTotalGlobalServices metric.Gauge) *GlobalServiceCache {
	return &GlobalServiceCache{
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
	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceName: svc.String(),
		logfields.ClusterName: svc.Cluster,
	})

	c.mutex.Lock()

	// Validate that the global service is known
	globalSvc, ok := c.byName[svc.NamespaceServiceName()]
	if !ok {
		globalSvc = newGlobalService()
		c.byName[svc.NamespaceServiceName()] = globalSvc
		scopedLog.Debugf("Created global service %s", svc.NamespaceServiceName())
		c.metricTotalGlobalServices.Set(float64(len(c.byName)))
	}

	scopedLog.Debugf("Updated service definition of remote cluster %#v", svc)

	globalSvc.ClusterServices[svc.Cluster] = svc
	c.mutex.Unlock()
}

// must be called with c.mutex held
func (c *GlobalServiceCache) delete(globalService *GlobalService, clusterName string, serviceNN types.NamespacedName) bool {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceName: serviceNN.String(),
		logfields.ClusterName: clusterName,
	})

	if _, ok := globalService.ClusterServices[clusterName]; !ok {
		scopedLog.Debug("Ignoring delete request for unknown cluster")
		return false
	}

	scopedLog.Debugf("Deleted service definition of remote cluster")
	delete(globalService.ClusterServices, clusterName)

	// After the last cluster service is removed, remove the global service
	if len(globalService.ClusterServices) == 0 {
		scopedLog.Debugf("Deleted global service %s", serviceNN.String())
		delete(c.byName, serviceNN)
		c.metricTotalGlobalServices.Set(float64(len(c.byName)))
	}

	return true
}

func (c *GlobalServiceCache) OnDelete(svc *serviceStore.ClusterService) bool {
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
	scopedLog.Debug("Delete event for service")

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if globalService, ok := c.byName[svc.NamespaceServiceName()]; ok {
		return c.delete(globalService, svc.Cluster, svc.NamespaceServiceName())
	} else {
		scopedLog.Debugf("Ignoring delete request for unknown global service")
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
	log logrus.FieldLogger

	cache *GlobalServiceCache

	onUpdate func(*serviceStore.ClusterService)
	onDelete func(*serviceStore.ClusterService)
}

// NewSharedServicesObserver returns an observer implementing the logic to convert
// and filter shared services notifications, update the global service cache and
// call the upstream handlers when appropriate.
func NewSharedServicesObserver(
	log logrus.FieldLogger, cache *GlobalServiceCache,
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
	scopedLog := r.log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
	scopedLog.Debug("Received remote service update event")

	// Short-circuit the handling of non-shared services
	if !svc.Shared {
		if r.cache.Has(svc) {
			scopedLog.Debug("Previously shared service is no longer shared: triggering deletion event")
			r.OnDelete(key)
		} else {
			scopedLog.Debug("Ignoring remote service update: service is not shared")
		}
		return
	}

	r.cache.OnUpdate(svc)
	r.onUpdate(svc)
}

// OnDelete is called when a service in a remote cluster is deleted
func (r *remoteServiceObserver) OnDelete(key store.NamedKey) {
	svc := &(key.(*serviceStore.ValidatingClusterService).ClusterService)
	scopedLog := r.log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
	scopedLog.Debug("Received remote service delete event")

	// Short-circuit the deletion logic if the service was not present (i.e., not shared)
	if !r.cache.OnDelete(svc) {
		scopedLog.Debug("Ignoring remote service delete. Service was not shared")
		return
	}

	r.onDelete(svc)
}
