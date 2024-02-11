// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// ServiceMerger is the interface to be implemented by the owner of local
// services. The functions have to merge service updates and deletions with
// local services to provide a shared view.
type ServiceMerger interface {
	MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)
	MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)
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

		// Short-circuit the handling of non-shared services
		if !svc.Shared {
			if mesh.globalServices.Has(svc) {
				scopedLog.Debug("Previously shared service is no longer shared: triggering deletion event")
				r.OnDelete(key)
			} else {
				scopedLog.Debug("Ignoring remote service update: service is not shared")
			}
			return
		}

		mesh.globalServices.OnUpdate(svc)

		if merger := mesh.conf.ServiceMerger; merger != nil {
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
		scopedLog.Debugf("Delete event of remote service %#v", svc)

		mesh := r.remoteCluster.mesh
		// Short-circuit the deletion logic if the service was not present (i.e., not shared)
		if !mesh.globalServices.OnDelete(svc) {
			scopedLog.Debugf("Ignoring remote service delete. Service was not shared")
			return
		}

		if merger := mesh.conf.ServiceMerger; merger != nil {
			merger.MergeExternalServiceDelete(svc, r.swg)
		} else {
			scopedLog.Debugf("Ignoring remote service delete. Missing merger function")
		}
	} else {
		log.Warningf("Received unexpected remote service delete object %+v", key)
	}
}
