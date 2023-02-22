// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package clustermesh

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// ServiceMerger is the interface to be implemented by the owner of local
// services. The functions have to merge service updates and deletions with
// local services to provide a shared view.
type ServiceMerger interface {
	MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)
	MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)
}

type globalService struct {
	clusterServices map[string]*serviceStore.ClusterService
}

func newGlobalService() *globalService {
	return &globalService{
		clusterServices: map[string]*serviceStore.ClusterService{},
	}
}

type globalServiceCache struct {
	clusterName string
	nodeName    string

	mutex  lock.RWMutex
	byName map[string]*globalService

	// metricTotalGlobalServices is the gauge metric for total of global services
	metricTotalGlobalServices *prometheus.GaugeVec
}

func newGlobalServiceCache(clusterName, nodeName string) *globalServiceCache {
	gsc := &globalServiceCache{
		clusterName: clusterName,
		nodeName:    nodeName,
		byName:      map[string]*globalService{},
		metricTotalGlobalServices: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "global_services",
			Help:      "The total number of global services in the cluster mesh",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName}),
	}

	_ = metrics.Register(gsc.metricTotalGlobalServices)
	return gsc
}

func (c *globalServiceCache) onUpdate(svc *serviceStore.ClusterService) {
	c.mutex.Lock()

	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceName: svc.String(),
		logfields.ClusterName: svc.Cluster,
	})

	// Validate that the global service is known
	globalSvc, ok := c.byName[svc.NamespaceServiceName()]
	if !ok {
		globalSvc = newGlobalService()
		c.byName[svc.NamespaceServiceName()] = globalSvc
		scopedLog.Debugf("Created global service %s", svc.NamespaceServiceName())
		c.metricTotalGlobalServices.WithLabelValues(c.clusterName, c.nodeName).Set(float64(len(c.byName)))
	}

	scopedLog.Debugf("Updated service definition of remote cluster %#v", svc)

	globalSvc.clusterServices[svc.Cluster] = svc
	c.mutex.Unlock()
}

// must be called with c.mutex held
func (c *globalServiceCache) delete(globalService *globalService, clusterName, serviceName string) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.ServiceName: serviceName,
		logfields.ClusterName: clusterName,
	})

	if _, ok := globalService.clusterServices[clusterName]; !ok {
		scopedLog.Debug("Ignoring delete request for unknown cluster")
		return
	}

	scopedLog.Debugf("Deleted service definition of remote cluster")
	delete(globalService.clusterServices, clusterName)

	// After the last cluster service is removed, remove the
	// global service
	if len(globalService.clusterServices) == 0 {
		scopedLog.Debugf("Deleted global service %s", serviceName)
		delete(c.byName, serviceName)
		c.metricTotalGlobalServices.WithLabelValues(c.clusterName, c.nodeName).Set(float64(len(c.byName)))
	}
}

func (c *globalServiceCache) onDelete(svc *serviceStore.ClusterService) {
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
	scopedLog.Debug("Delete event for service")

	c.mutex.Lock()
	if globalService, ok := c.byName[svc.NamespaceServiceName()]; ok {
		c.delete(globalService, svc.Cluster, svc.NamespaceServiceName())
	} else {
		scopedLog.Debugf("Ignoring delete request for unknown global service")
	}
	c.mutex.Unlock()
}

func (c *globalServiceCache) onClusterDelete(clusterName string) {
	scopedLog := log.WithFields(logrus.Fields{logfields.ClusterName: clusterName})
	scopedLog.Debugf("Cluster deletion event")

	c.mutex.Lock()
	for serviceName, globalService := range c.byName {
		c.delete(globalService, clusterName, serviceName)
	}
	c.mutex.Unlock()
}

// size returns the number of global services in the cache
func (c *globalServiceCache) size() (num int) {
	c.mutex.RLock()
	num = len(c.byName)
	c.mutex.RUnlock()
	return
}

type remoteServiceObserver struct {
	remoteCluster *remoteCluster
	// swg provides a mechanism to known when the services were synchronized
	// with the datapath.
	swg *lock.StoppableWaitGroup
}

// OnUpdate is called when a service in a remote cluster is updated
func (r *remoteServiceObserver) OnUpdate(key store.Key) {
	if svc, ok := key.(*serviceStore.ClusterService); ok {
		scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
		scopedLog.Debugf("Update event of remote service %#v", svc)

		mesh := r.remoteCluster.mesh
		mesh.globalServices.onUpdate(svc)

		if merger := mesh.conf.ServiceMerger; merger != nil {
			r.swg.Add()
			merger.MergeExternalServiceUpdate(svc, r.swg)
		} else {
			scopedLog.Debugf("Ignoring remote service update. Missing merger function")
		}
	} else {
		log.Warningf("Received unexpected remote service update object %+v", key)
	}
}

// OnDelete is called when a service in a remote cluster is deleted
func (r *remoteServiceObserver) OnDelete(key store.NamedKey) {
	if svc, ok := key.(*serviceStore.ClusterService); ok {
		scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
		scopedLog.Debugf("Update event of remote service %#v", svc)

		mesh := r.remoteCluster.mesh
		mesh.globalServices.onDelete(svc)

		if merger := mesh.conf.ServiceMerger; merger != nil {
			r.swg.Add()
			merger.MergeExternalServiceDelete(svc, r.swg)
		} else {
			scopedLog.Debugf("Ignoring remote service update. Missing merger function")
		}
	} else {
		log.Warningf("Received unexpected remote service delete object %+v", key)
	}
}
