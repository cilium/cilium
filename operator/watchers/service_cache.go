// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

// CacheAction is the type of action that was performed on the cache
type CacheAction int

const (
	// UpdateService reflects that the service was updated or added
	UpdateService CacheAction = iota

	// DeleteService reflects that the service was deleted
	DeleteService
)

// String returns the cache action as a string
func (c CacheAction) String() string {
	switch c {
	case UpdateService:
		return "service-updated"
	case DeleteService:
		return "service-deleted"
	default:
		return "unknown"
	}
}

// ServiceEvent is emitted via the Events channel of ServiceCache and describes
// the change that occurred in the cache
type ServiceEvent struct {
	// Action is the action that was performed in the cache
	Action CacheAction

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

	// SWG provides a mechanism to detect if a service was synchronized with
	// the datapath.
	SWG *lock.StoppableWaitGroup
}

// ServiceNotification is a slimmed down version of a ServiceEvent. In particular
// notifications are optional and thus do not contain a wait group to allow
// producers to wait for the notification to be consumed.
type ServiceNotification struct {
	Action       CacheAction
	ID           k8s.ServiceID
	Service      *k8s.Service
	OldService   *k8s.Service
	Endpoints    *k8s.Endpoints
	OldEndpoints *k8s.Endpoints
}

// ServiceCache is a list of services correlated with the matching endpoints.
// The Events member will receive events as services.
type ServiceCache struct {
	// Events may only be read by single consumer. The consumer must acknowledge
	// every event by calling Done() on the ServiceEvent.SWG.
	Events     <-chan ServiceEvent
	sendEvents chan<- ServiceEvent

	// mutex protects the maps below including the concurrent access of each
	// value.
	mutex    lock.RWMutex
	services map[k8s.ServiceID]*k8s.Service
	// endpoints maps a service to a map of EndpointSlices. In case the cluster
	// is still using the v1.Endpoints, the key used in the internal map of
	// EndpointSlices is the v1.Endpoint name.
	endpoints map[k8s.ServiceID]*k8s.EndpointSlices

	nodeAddressing types.NodeAddressing
}

// NewServiceCache returns a new ServiceCache
func NewServiceCache(nodeAddressing types.NodeAddressing) *ServiceCache {
	events := make(chan ServiceEvent, option.Config.K8sServiceCacheSize)

	return &ServiceCache{
		services:       map[k8s.ServiceID]*k8s.Service{},
		endpoints:      map[k8s.ServiceID]*k8s.EndpointSlices{},
		Events:         events,
		sendEvents:     events,
		nodeAddressing: nodeAddressing,
	}
}

func (s *ServiceCache) emitEvent(event ServiceEvent) {
	s.sendEvents <- event
}

// GetServiceIP returns a random L3n4Addr that is backing the given Service ID.
// The returned IP is with external scope since its string representation might
// be used for net Dialer.
func (s *ServiceCache) GetServiceIP(svcID k8s.ServiceID) *loadbalancer.L3n4Addr {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	svc := s.services[svcID]
	if svc == nil || len(svc.FrontendIPs) == 0 || len(svc.Ports) == 0 {
		return nil
	}

	feIP := ip.GetIPFromListByFamily(svc.FrontendIPs, option.Config.EnableIPv4)
	if feIP == nil {
		return nil
	}

	for _, port := range svc.Ports {
		return loadbalancer.NewL3n4Addr(port.Protocol, cmtypes.MustAddrClusterFromIP(feIP), port.Port,
			loadbalancer.ScopeExternal)
	}
	return nil
}

// UpdateService parses a Kubernetes service and adds or updates it in the
// ServiceCache. Returns the k8s.ServiceID unless the Kubernetes service could not
// be parsed and a bool to indicate whether the service was changed in the
// cache or not.
func (s *ServiceCache) UpdateService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) k8s.ServiceID {
	svcID, newService := k8s.ParseService(k8sSvc, s.nodeAddressing)
	if newService == nil {
		return svcID
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
		swg.Add()
		s.emitEvent(ServiceEvent{
			Action:       UpdateService,
			ID:           svcID,
			Service:      newService,
			OldService:   oldService,
			Endpoints:    endpoints,
			OldEndpoints: endpoints,
			SWG:          swg,
		})
	}

	return svcID
}

// DeleteService parses a Kubernetes service and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) {
	svcID := k8s.ParseServiceID(k8sSvc)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, serviceOK := s.services[svcID]
	endpoints, _ := s.correlateEndpoints(svcID)
	delete(s.services, svcID)

	if serviceOK {
		swg.Add()
		s.emitEvent(ServiceEvent{
			Action:    DeleteService,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
			SWG:       swg,
		})
	}
}

// UpdateEndpoints parses a Kubernetes endpoints and adds or updates it in the
// ServiceCache. Returns the k8s.ServiceID unless the Kubernetes endpoints could not
// be parsed and a bool to indicate whether the endpoints was changed in the
// cache or not.
func (s *ServiceCache) UpdateEndpoints(newEndpoints *k8s.Endpoints, swg *lock.StoppableWaitGroup) (k8s.ServiceID, *k8s.Endpoints) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	esID := newEndpoints.EndpointSliceID

	var oldEPs *k8s.Endpoints
	eps, ok := s.endpoints[esID.ServiceID]
	if ok {
		oldEPs = eps.EpSlices()[esID.EndpointSliceName]
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
		swg.Add()
		s.emitEvent(ServiceEvent{
			Action:       UpdateService,
			ID:           esID.ServiceID,
			Service:      svc,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWG:          swg,
		})
	}

	return esID.ServiceID, endpoints
}

// DeleteEndpoints parses a Kubernetes endpoints and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteEndpoints(svcID k8s.EndpointSliceID, swg *lock.StoppableWaitGroup) k8s.ServiceID {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var oldEPs *k8s.Endpoints
	svc, serviceOK := s.services[svcID.ServiceID]
	eps, ok := s.endpoints[svcID.ServiceID]
	if ok {
		oldEPs = eps.EpSlices()[svcID.EndpointSliceName].DeepCopy() // copy for passing to ServiceEvent
		isEmpty := eps.Delete(svcID.EndpointSliceName)
		if isEmpty {
			delete(s.endpoints, svcID.ServiceID)
		}
	}
	endpoints, _ := s.correlateEndpoints(svcID.ServiceID)

	if serviceOK {
		swg.Add()
		event := ServiceEvent{
			Action:       UpdateService,
			ID:           svcID.ServiceID,
			Service:      svc,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWG:          swg,
		}

		s.emitEvent(event)
	}

	return svcID.ServiceID
}

// filterEndpoints filters local endpoints by using k8s service heuristics.
// For now it only implements the topology aware hints.
func (s *ServiceCache) filterEndpoints(localEndpoints *k8s.Endpoints, svc *k8s.Service) *k8s.Endpoints {
	if svc == nil || !svc.TopologyAware {
		return localEndpoints
	}

	// The node doesn't have the zone label set, so we cannot filter endpoints
	// by zone. Therefore, return all endpoints.
	return localEndpoints
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
func (s *ServiceCache) correlateEndpoints(id k8s.ServiceID) (*k8s.Endpoints, bool) {
	endpoints := k8s.NewEndpoints()

	localEndpoints := s.endpoints[id].GetEndpoints()
	svc, svcFound := s.services[id]

	hasLocalEndpoints := localEndpoints != nil
	if hasLocalEndpoints {
		localEndpoints = s.filterEndpoints(localEndpoints, svc)

		for ip, e := range localEndpoints.Backends {
			e.Preferred = svcFound && svc.IncludeExternal && svc.ServiceAffinity == k8s.ServiceAffinityLocal
			endpoints.Backends[ip] = e.DeepCopy()
		}
	}

	// Report the service as ready if a local endpoints object exists or if
	// external endpoints have been identified
	return endpoints, hasLocalEndpoints
}
