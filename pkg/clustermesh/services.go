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
	"github.com/cilium/cilium/pkg/service"
)

// ServiceMerger is the interface to be implemented by the owner of local
// services. The functions have to merge service updates and deletions with
// local services to provide a shared view.
type ServiceMerger interface {
	MergeExternalServiceUpdate(service *service.ClusterService)
	MergeExternalServiceDelete(service *service.ClusterService)
}

type globalService struct {
	clusterServices map[string]*service.ClusterService
}

func newGlobalService() *globalService {
	return &globalService{
		clusterServices: map[string]*service.ClusterService{},
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

func (c *globalServiceCache) onUpdate(svc *service.ClusterService) {
	c.mutex.Lock()

	// Validate that the global service is known
	globalSvc, ok := c.byName[svc.NamespaceServiceName()]
	if !ok {
		globalSvc = newGlobalService()
		c.byName[svc.NamespaceServiceName()] = globalSvc
	}

	globalSvc.clusterServices[svc.Cluster] = svc
	c.mutex.Unlock()
}

// must be called with c.mutex held
func (c *globalServiceCache) delete(globalService *globalService, clusterName, serviceName string) {
	if _, ok := globalService.clusterServices[clusterName]; !ok {
		return
	}

	delete(globalService.clusterServices, clusterName)

	// After the last cluster service is removed, remove the
	// global service
	if len(globalService.clusterServices) == 0 {
		delete(c.byName, serviceName)
	}
}

func (c *globalServiceCache) onDelete(svc *service.ClusterService) {
	c.mutex.Lock()
	if globalService, ok := c.byName[svc.NamespaceServiceName()]; ok {
		c.delete(globalService, svc.NamespaceServiceName(), svc.Cluster)
	}
	c.mutex.Unlock()
}

func (c *globalServiceCache) onClusterDelete(clusterName string) {
	c.mutex.Lock()
	for serviceName, globalService := range c.byName {
		c.delete(globalService, serviceName, clusterName)
	}
	c.mutex.Unlock()
}

type remoteServiceObserver struct {
	remoteCluster *remoteCluster
}

// OnUpdate is called when a service in a remote cluster is updated
func (r *remoteServiceObserver) OnUpdate(key store.Key) {
	if svc, ok := key.(*service.ClusterService); ok {
		mesh := r.remoteCluster.mesh
		mesh.globalServices.onUpdate(svc)

		if merger := mesh.conf.ServiceMerger; merger != nil {
			merger.MergeExternalServiceUpdate(svc)
		}
	} else {
		log.Warningf("Received unexpected remote service update object %+v", key)
	}
}

// OnDelete is called when a service in a remote cluster is deleted
func (r *remoteServiceObserver) OnDelete(key store.Key) {
	if svc, ok := key.(*service.ClusterService); ok {
		mesh := r.remoteCluster.mesh
		mesh.globalServices.onDelete(svc)

		if merger := mesh.conf.ServiceMerger; merger != nil {
			merger.MergeExternalServiceDelete(svc)
		}
	} else {
		log.Warningf("Received unexpected remote service delete object %+v", key)
	}
}
