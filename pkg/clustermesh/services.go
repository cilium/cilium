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

package clustermesh

import (
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	serviceStore "github.com/cilium/cilium/pkg/service/store"

	"github.com/sirupsen/logrus"
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
	mutex  lock.RWMutex
	byName map[string]*globalService
}

func newGlobalServiceCache() *globalServiceCache {
	return &globalServiceCache{
		byName: map[string]*globalService{},
	}
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
	}
}

func (c *globalServiceCache) onDelete(svc *serviceStore.ClusterService) {
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
	scopedLog.Debug("Delete event for service")

	c.mutex.Lock()
	if globalService, ok := c.byName[svc.NamespaceServiceName()]; ok {
		c.delete(globalService, svc.NamespaceServiceName(), svc.Cluster)
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
		c.delete(globalService, serviceName, clusterName)
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
