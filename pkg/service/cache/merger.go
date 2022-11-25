package cache

import (
	"github.com/sirupsen/logrus"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/store"
)

// MergeExternalServiceUpdate merges a cluster service of a remote cluster into
// the local service cache. The service endpoints are stored as external endpoints
// and are correlated on demand with local services via correlateEndpoints().
func (sc *serviceCache) MergeExternalServiceUpdate(service *store.ClusterService) {
	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.mergeServiceUpdateLocked(service, nil)
}

func (sc *serviceCache) mergeServiceUpdateLocked(service *store.ClusterService, oldService *Service) {
	id := ServiceID{Name: service.Name, Namespace: service.Namespace}
	scopedLog := sc.Log.WithFields(logrus.Fields{logfields.ServiceName: service.String()})

	externalEndpoints, ok := sc.externalEndpoints[id]
	if !ok {
		externalEndpoints = newExternalEndpoints()
		sc.externalEndpoints[id] = externalEndpoints
	}

	// we don't need to check if the current cluster is remote or local,
	// as externalEndpoints should not have any local cluster endpoints anyway.
	if service.IncludeExternal && !service.Shared {
		delete(externalEndpoints, service.Cluster)
	} else {
		scopedLog.Debugf("Updating backends to %+v", service.Backends)
		backends := map[cmtypes.AddrCluster]*k8s.Backend{}
		for ipString, portConfig := range service.Backends {
			backends[cmtypes.MustParseAddrCluster(ipString)] = &k8s.Backend{Ports: portConfig}
		}
		externalEndpoints[service.Cluster] = &Endpoints{
			Backends: backends,
		}
	}

	svc, ok := sc.services[id]
	endpoints, serviceReady := sc.correlateEndpoints(id)

	// Only send event notification if service is ready.
	if ok && serviceReady {
		sc.mcast.emit(&ServiceEvent{
			Action:     UpdateService,
			ID:         id,
			Service:    svc,
			OldService: oldService,
			Endpoints:  endpoints,
		})
	}
}

func (sc *serviceCache) MergeExternalServiceDelete(service *store.ClusterService) {
	panic("TBD")
}

func (sc *serviceCache) MergeClusterServiceUpdate(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	panic("TBD")
}

func (sc *serviceCache) MergeClusterServiceDelete(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	panic("TBD")
}
