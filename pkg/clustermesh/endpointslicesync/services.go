// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

type remoteServiceObserver struct {
	globalServices  *common.GlobalServiceCache
	meshPodInformer *meshPodInformer
}

// OnUpdate is called when a service in a remote cluster is updated
func (r *remoteServiceObserver) OnUpdate(key store.Key) {
	if svc, ok := key.(*serviceStore.ClusterService); ok {
		scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
		scopedLog.Debugf("Update event of remote service %#v", svc)

		// Short-circuit the handling of non-shared services
		if !svc.Shared {
			if r.globalServices.Has(svc) {
				scopedLog.Debug("Previously shared service is no longer shared: triggering deletion event")
				r.OnDelete(key)
			} else {
				scopedLog.Debug("Ignoring remote service update: service is not shared")
			}
			return
		}

		r.globalServices.OnUpdate(svc)
		r.meshPodInformer.onClusterServiceUpdate(svc)
	} else {
		log.Warningf("Received unexpected remote service update object %+v", key)
	}
}

// OnDelete is called when a service in a remote cluster is deleted
func (r *remoteServiceObserver) OnDelete(key store.NamedKey) {
	if svc, ok := key.(*serviceStore.ClusterService); ok {
		scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: svc.String()})
		scopedLog.Debugf("Delete event of remote service %#v", svc)

		// Short-circuit the deletion logic if the service was not present (i.e., not shared)
		if !r.globalServices.OnDelete(svc) {
			scopedLog.Debugf("Ignoring remote service delete. Service was not shared")
			return
		}

		r.meshPodInformer.onClusterServiceDelete(svc)
	} else {
		log.Warningf("Received unexpected remote service delete object %+v", key)
	}
}
