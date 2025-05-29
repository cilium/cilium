// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// cacheAction is the type of action that was performed on the cache
type cacheAction int

const (
	// UpdateService reflects that the service was updated or added
	UpdateService cacheAction = iota

	// DeleteService reflects that the service was deleted
	DeleteService
)

// String returns the cache action as a string
func (c cacheAction) String() string {
	switch c {
	case UpdateService:
		return "service-updated"
	case DeleteService:
		return "service-deleted"
	default:
		return "unknown"
	}
}

// serviceEvent is emitted via the Events channel of ServiceCache and describes
// the change that occurred in the cache
type serviceEvent struct {
	// Action is the action that was performed in the cache
	Action cacheAction

	// ID is the identified of the service
	ID k8s.ServiceID

	// Service is the service structure
	Service *k8s.Service

	// OldService is the old service structure
	OldService *k8s.Service

	// Endpoints is the endpoints structured correlated with the service
	Endpoints *k8s.Endpoints

	// OldEndpoints is old endpoints structure.
	OldEndpoints *k8s.Endpoints

	// SWGDone marks the event as processed. The underlying StoppableWaitGroup
	// provides a mechanism to detect if a service was synchronized with
	// the datapath.
	SWGDone lock.DoneFunc
}

type ServiceMutators []func(svc *slim_corev1.Service, svcInfo *k8s.Service)

// serviceCache is a list of services correlated with the matching endpoints.
// The Events member will receive events as services.
type serviceCache struct {
	logger *slog.Logger

	// Events may only be read by single consumer. The consumer must acknowledge
	// every event by calling Done() on the ServiceEvent.SWG.
	events     <-chan serviceEvent
	sendEvents chan<- serviceEvent

	// mutex protects the maps below including the concurrent access of each
	// value.
	mutex    lock.RWMutex
	services map[k8s.ServiceID]*k8s.Service
	// endpoints maps a service to a map of EndpointSlices. In case the cluster
	// is still using the v1.Endpoints, the key used in the internal map of
	// EndpointSlices is the v1.Endpoint name.
	endpoints map[k8s.ServiceID]*k8s.EndpointSlices

	// externalEndpoints is a list of additional service backends derived from source other than the local cluster
	externalEndpoints map[k8s.ServiceID]externalEndpoints

	serviceMutators []func(svc *slim_corev1.Service, svcInfo *k8s.Service)
}

// newServiceCache returns a new ServiceCache
func newServiceCache(logger *slog.Logger, serviceMutators ServiceMutators) *serviceCache {
	events := make(chan serviceEvent, option.Config.K8sServiceCacheSize)

	return &serviceCache{
		logger:            logger,
		services:          map[k8s.ServiceID]*k8s.Service{},
		endpoints:         map[k8s.ServiceID]*k8s.EndpointSlices{},
		externalEndpoints: map[k8s.ServiceID]externalEndpoints{},
		events:            events,
		sendEvents:        events,
		serviceMutators:   serviceMutators,
	}
}

func (sc *serviceCache) Events() <-chan serviceEvent {
	return sc.events
}

func (s *serviceCache) emitEvent(event serviceEvent) {
	s.sendEvents <- event
}

// UpdateService parses a Kubernetes service and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes service could not
// be parsed and a bool to indicate whether the service was changed in the
// cache or not.
func (s *serviceCache) UpdateService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) k8s.ServiceID {
	var addrs []netip.Addr

	svcID, newService := k8s.ParseService(s.logger, loadbalancer.DefaultConfig, k8sSvc, addrs)
	if newService == nil {
		return svcID
	}

	for _, mutator := range s.serviceMutators {
		mutator(k8sSvc, newService)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, ok := s.services[svcID]
	if ok {
		if oldService.DeepEqual(newService) {
			return svcID
		}
	}

	s.services[svcID] = newService

	// Check if the corresponding Endpoints resource is already available
	endpoints, serviceReady := s.correlateEndpoints(svcID)
	if serviceReady {
		s.emitEvent(serviceEvent{
			Action:       UpdateService,
			ID:           svcID,
			Service:      newService,
			OldService:   oldService,
			Endpoints:    endpoints,
			OldEndpoints: endpoints,
			SWGDone:      swg.Add(),
		})
	}

	return svcID
}

// DeleteService parses a Kubernetes service and removes it from the
// ServiceCache
func (s *serviceCache) DeleteService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) {
	svcID := k8s.ParseServiceID(k8sSvc)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, serviceOK := s.services[svcID]
	endpoints, _ := s.correlateEndpoints(svcID)
	delete(s.services, svcID)

	if serviceOK {
		s.emitEvent(serviceEvent{
			Action:    DeleteService,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
			SWGDone:   swg.Add(),
		})
	}
}

// UpdateEndpoints parses a Kubernetes endpoints and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes endpoints could not
// be parsed and a bool to indicate whether the endpoints was changed in the
// cache or not.
func (s *serviceCache) UpdateEndpoints(newEndpoints *k8s.Endpoints, swg *lock.StoppableWaitGroup) (k8s.ServiceID, *k8s.Endpoints) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	esID := newEndpoints.EndpointSliceID

	var oldEPs *k8s.Endpoints
	eps, ok := s.endpoints[esID.ServiceID]
	if ok {
		oldEPs = eps.Get(esID.EndpointSliceName)
		if oldEPs.DeepEqual(newEndpoints) {
			return esID.ServiceID, newEndpoints
		}
	} else {
		eps = k8s.NewEndpointsSlices()
		s.endpoints[esID.ServiceID] = eps
	}

	eps.Upsert(esID.EndpointSliceName, newEndpoints)

	// Check if the corresponding Endpoints resource is already available
	svc, ok := s.services[esID.ServiceID]
	endpoints, serviceReady := s.correlateEndpoints(esID.ServiceID)
	if ok && serviceReady {
		s.emitEvent(serviceEvent{
			Action:       UpdateService,
			ID:           esID.ServiceID,
			Service:      svc,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWGDone:      swg.Add(),
		})
	}

	return esID.ServiceID, endpoints
}

// DeleteEndpoints parses a Kubernetes endpoints and removes it from the
// ServiceCache
func (s *serviceCache) DeleteEndpoints(svcID k8s.EndpointSliceID, swg *lock.StoppableWaitGroup) k8s.ServiceID {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var oldEPs *k8s.Endpoints
	svc, serviceOK := s.services[svcID.ServiceID]
	eps, ok := s.endpoints[svcID.ServiceID]
	if ok {
		oldEPs = eps.Get(svcID.EndpointSliceName).DeepCopy() // copy for passing to ServiceEvent
		isEmpty := eps.Delete(svcID.EndpointSliceName)
		if isEmpty {
			delete(s.endpoints, svcID.ServiceID)
		}
	}
	endpoints, _ := s.correlateEndpoints(svcID.ServiceID)

	if serviceOK {
		event := serviceEvent{
			Action:       UpdateService,
			ID:           svcID.ServiceID,
			Service:      svc,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWGDone:      swg.Add(),
		}

		s.emitEvent(event)
	}

	return svcID.ServiceID
}

// correlateEndpoints builds a combined Endpoints of the local endpoints and
// all external endpoints if the service is marked as a global service. Also
// returns a boolean that indicates whether the service is ready to be plumbed,
// this is true if:
// A local endpoints resource is present. Regardless whether the
//
//	endpoints resource contains actual backends or not.
//
// OR Remote endpoints exist which correlate to the service.
func (s *serviceCache) correlateEndpoints(id k8s.ServiceID) (*k8s.Endpoints, bool) {
	endpoints := s.endpoints[id].GetEndpoints()
	svc, svcFound := s.services[id]

	hasLocalEndpoints := endpoints != nil
	if hasLocalEndpoints {
		for _, e := range endpoints.Backends {
			// The endpoints returned by GetEndpoints are already deep copies,
			// hence we can mutate them in-place without problems.
			e.Preferred = svcFound && svc.IncludeExternal && svc.ServiceAffinity == annotation.ServiceAffinityLocal
		}
	} else {
		endpoints = k8s.NewEndpoints()
	}

	var hasExternalEndpoints bool
	if svcFound && svc.IncludeExternal {
		externalEndpoints, ok := s.externalEndpoints[id]
		hasExternalEndpoints = ok && len(externalEndpoints.endpoints) > 0
		if hasExternalEndpoints {
			// remote cluster endpoints already contain all Endpoints from all
			// EndpointSlices so no need to search the endpoints of a particular
			// EndpointSlice.
			for clusterName, remoteClusterEndpoints := range externalEndpoints.endpoints {
				for ip, e := range remoteClusterEndpoints.Backends {
					if _, ok := endpoints.Backends[ip]; ok {
						s.logger.Warn(
							"Conflicting service backend IP",
							logfields.K8sSvcName, id.Name,
							logfields.K8sNamespace, id.Namespace,
							logfields.IPAddr, ip,
							logfields.ClusterName, clusterName,
						)
					} else {
						e.Preferred = svc.ServiceAffinity == annotation.ServiceAffinityRemote
						endpoints.Backends[ip] = e.DeepCopy()
					}
				}
			}
		}
	}

	// Report the service as ready if a local endpoints object exists or if
	// external endpoints have been identified
	return endpoints, hasLocalEndpoints || hasExternalEndpoints
}

// externalEndpoints is the collection of external endpoints in all remote
// clusters. The map key is the name of the remote cluster.
type externalEndpoints struct {
	endpoints map[string]*k8s.Endpoints
}
