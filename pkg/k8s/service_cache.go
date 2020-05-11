// Copyright 2018-2019 Authors of Cilium
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

package k8s

import (
	"net"

	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
)

// CacheAction is the type of action that was performed on the cache
type CacheAction int

const (
	// UpdateService reflects that the service was updated or added
	UpdateService CacheAction = iota

	// DeleteService reflects that the service was deleted
	DeleteService

	// UpdateIngress reflects that the ingress was updated or added
	UpdateIngress

	// DeleteIngress reflects that the ingress was deleted
	DeleteIngress
)

// String returns the cache action as a string
func (c CacheAction) String() string {
	switch c {
	case UpdateService:
		return "service-updated"
	case DeleteService:
		return "service-deleted"
	case UpdateIngress:
		return "ingress-updated"
	case DeleteIngress:
		return "ingress-deleted"
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
	ID ServiceID

	// Service is the service structure
	Service *Service

	// OldService is the service structure
	OldService *Service

	// Endpoints is the endpoints structured correlated with the service
	Endpoints *Endpoints
}

// ServiceCache is a list of services and ingresses correlated with the
// matching endpoints. The Events member will receive events as services and
// ingresses
type ServiceCache struct {
	Events chan ServiceEvent

	// mutex protects the maps below including the concurrent access of each
	// value.
	mutex     lock.RWMutex
	services  map[ServiceID]*Service
	endpoints map[ServiceID]*Endpoints
	ingresses map[ServiceID]*Service

	// externalEndpoints is a list of additional service backends derived from source other than the local cluster
	externalEndpoints map[ServiceID]externalEndpoints
}

// NewServiceCache returns a new ServiceCache
func NewServiceCache() ServiceCache {
	return ServiceCache{
		services:          map[ServiceID]*Service{},
		endpoints:         map[ServiceID]*Endpoints{},
		ingresses:         map[ServiceID]*Service{},
		externalEndpoints: map[ServiceID]externalEndpoints{},
		Events:            make(chan ServiceEvent, option.Config.K8sServiceCacheSize),
	}
}

// GetServiceIP returns a random L3n4Addr that is backing the given Service ID.
func (s *ServiceCache) GetServiceIP(svcID ServiceID) *loadbalancer.L3n4Addr {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	svc := s.services[svcID]
	if svc == nil {
		return nil
	}
	for _, port := range svc.Ports {
		return loadbalancer.NewL3n4Addr(port.Protocol, svc.FrontendIP, port.Port)
	}
	return nil
}

// UpdateService parses a Kubernetes service and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes service could not
// be parsed and a bool to indicate whether the service was changed in the
// cache or not.
func (s *ServiceCache) UpdateService(k8sSvc *types.Service) ServiceID {
	svcID, newService := ParseService(k8sSvc)
	if newService == nil {
		return svcID
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, ok := s.services[svcID]
	if ok {
		if oldService.DeepEquals(newService) {
			return svcID
		}
	}

	s.services[svcID] = newService

	// Check if the corresponding Endpoints resource is already available
	endpoints, serviceReady := s.correlateEndpoints(svcID)
	if serviceReady {
		s.Events <- ServiceEvent{
			Action:     UpdateService,
			ID:         svcID,
			Service:    newService,
			OldService: oldService,
			Endpoints:  endpoints,
		}
	}

	return svcID
}

// DeleteService parses a Kubernetes service and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteService(k8sSvc *types.Service) {
	svcID := ParseServiceID(k8sSvc)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, serviceOK := s.services[svcID]
	endpoints, _ := s.correlateEndpoints(svcID)
	delete(s.services, svcID)

	if serviceOK {
		s.Events <- ServiceEvent{
			Action:    DeleteService,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
		}
	}
}

// UpdateEndpoints parses a Kubernetes endpoints and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes endpoints could not
// be parsed and a bool to indicate whether the endpoints was changed in the
// cache or not.
func (s *ServiceCache) UpdateEndpoints(k8sEndpoints *types.Endpoints) (ServiceID, *Endpoints) {
	svcID, newEndpoints := ParseEndpoints(k8sEndpoints)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if oldEndpoints, ok := s.endpoints[svcID]; ok {
		if oldEndpoints.DeepEquals(newEndpoints) {
			return svcID, newEndpoints
		}
	}

	s.endpoints[svcID] = newEndpoints

	// Check if the corresponding Endpoints resource is already available
	service, ok := s.services[svcID]
	endpoints, serviceReady := s.correlateEndpoints(svcID)
	if ok && serviceReady {
		s.Events <- ServiceEvent{
			Action:    UpdateService,
			ID:        svcID,
			Service:   service,
			Endpoints: endpoints,
		}
	}

	return svcID, newEndpoints
}

// DeleteEndpoints parses a Kubernetes endpoints and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteEndpoints(k8sEndpoints *types.Endpoints) ServiceID {
	svcID := ParseEndpointsID(k8sEndpoints)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	service, serviceOK := s.services[svcID]
	delete(s.endpoints, svcID)
	endpoints, _ := s.correlateEndpoints(svcID)

	if serviceOK {
		event := ServiceEvent{
			Action:    UpdateService,
			ID:        svcID,
			Service:   service,
			Endpoints: endpoints,
		}

		s.Events <- event
	}

	return svcID
}

// UpdateIngress parses a Kubernetes ingress and adds or updates it in the
// ServiceCache.
func (s *ServiceCache) UpdateIngress(ingress *types.Ingress, host net.IP) (ServiceID, error) {
	svcID, newService, err := ParseIngress(ingress, host)
	if err != nil {
		return svcID, err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if oldService, ok := s.ingresses[svcID]; ok {
		if oldService.DeepEquals(newService) {
			return svcID, nil
		}
	}

	s.ingresses[svcID] = newService

	s.Events <- ServiceEvent{
		Action:  UpdateIngress,
		ID:      svcID,
		Service: newService,
	}

	return svcID, nil
}

// DeleteIngress parses a Kubernetes ingress and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteIngress(ingress *types.Ingress) {
	svcID := ParseIngressID(ingress)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, ok := s.ingresses[svcID]
	endpoints := s.endpoints[svcID]
	delete(s.ingresses, svcID)

	if ok {
		s.Events <- ServiceEvent{
			Action:    DeleteIngress,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
		}
	}
}

// FrontendList is the list of all k8s service frontends
type FrontendList map[string]struct{}

// LooseMatch returns true if the provided frontend is found in the
// FrontendList. If the frontend has a protocol value set, it only matches a
// k8s service with a matching protocol. If no protocol is set, any k8s service
// matching frontend IP and port is considered a match, regardless of protocol.
func (l FrontendList) LooseMatch(frontend loadbalancer.L3n4Addr) (exists bool) {
	switch frontend.Protocol {
	case loadbalancer.NONE:
		for _, protocol := range loadbalancer.AllProtocols {
			frontend.Protocol = protocol
			_, exists = l[frontend.StringWithProtocol()]
			if exists {
				return
			}
		}

	// If the protocol is set, perform an exact match
	default:
		_, exists = l[frontend.StringWithProtocol()]
	}
	return
}

// UniqueServiceFrontends returns all services known to the service cache as a
// map, indexed by the string representation of a loadbalancer.L3n4Addr
func (s *ServiceCache) UniqueServiceFrontends() FrontendList {
	uniqueFrontends := FrontendList{}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, svc := range s.services {
		for _, p := range svc.Ports {
			address := loadbalancer.L3n4Addr{
				IP:     svc.FrontendIP,
				L4Addr: *p.L4Addr,
			}

			uniqueFrontends[address.StringWithProtocol()] = struct{}{}
		}
		for _, nodePortFEs := range svc.NodePorts {
			for _, fe := range nodePortFEs {
				uniqueFrontends[fe.StringWithProtocol()] = struct{}{}
			}
		}
	}

	return uniqueFrontends
}

// correlateEndpoints builds a combined Endpoints of the local endpoints and
// all external endpoints if the service is marked as a global service. Also
// returns a boolean that indicates whether the service is ready to be plumbed,
// this is true if:
// IF If ta local endpoints resource is present. Regardless whether the
//    endpoints resource contains actual backends or not.
// OR Remote endpoints exist which correlate to the service.
func (s *ServiceCache) correlateEndpoints(id ServiceID) (*Endpoints, bool) {
	endpoints := newEndpoints()

	localEndpoints, hasLocalEndpoints := s.endpoints[id]
	if hasLocalEndpoints {
		for ip, e := range localEndpoints.Backends {
			endpoints.Backends[ip] = e
		}
	}

	svc, hasExternalService := s.services[id]
	if hasExternalService && svc.IncludeExternal {
		externalEndpoints, hasExternalEndpoints := s.externalEndpoints[id]
		if hasExternalEndpoints {
			for clusterName, remoteClusterEndpoints := range externalEndpoints.endpoints {
				if clusterName == option.Config.ClusterName {
					continue
				}

				for ip, e := range remoteClusterEndpoints.Backends {
					if _, ok := endpoints.Backends[ip]; ok {
						log.WithFields(logrus.Fields{
							logfields.K8sSvcName:   id.Name,
							logfields.K8sNamespace: id.Namespace,
							logfields.IPAddr:       ip,
							"cluster":              clusterName,
						}).Warning("Conflicting service backend IP")
					} else {
						endpoints.Backends[ip] = e
					}
				}
			}
		}
	}

	// Report the service as ready if a local endpoints object exists or if
	// external endpoints have have been identified
	return endpoints, hasLocalEndpoints || len(endpoints.Backends) > 0
}

// MergeExternalServiceUpdate merges a cluster service of a remote cluster into
// the local service cache. The service endpoints are stored as external endpoints
// and are correlated on demand with local services via correlateEndpoints().
func (s *ServiceCache) MergeExternalServiceUpdate(service *service.ClusterService) {
	id := ServiceID{Name: service.Name, Namespace: service.Namespace}
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: service.String()})

	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		scopedLog.Debug("Not merging external service. Own cluster")
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	externalEndpoints, ok := s.externalEndpoints[id]
	if !ok {
		externalEndpoints = newExternalEndpoints()
		s.externalEndpoints[id] = externalEndpoints
	}

	scopedLog.Debugf("Updating backends to %+v", service.Backends)
	externalEndpoints.endpoints[service.Cluster] = &Endpoints{
		Backends: service.Backends,
	}

	svc, ok := s.services[id]

	endpoints, serviceReady := s.correlateEndpoints(id)

	// Only send event notification if service is shared and ready.
	// External endpoints are still tracked but correlation will not happen
	// until the service is marked as shared.
	if ok && svc.Shared && serviceReady {
		s.Events <- ServiceEvent{
			Action:    UpdateService,
			ID:        id,
			Service:   svc,
			Endpoints: endpoints,
		}
	}
}

// MergeExternalServiceDelete merges the deletion of a cluster service in a
// remote cluster into the local service cache. The service endpoints are
// stored as external endpoints and are correlated on demand with local
// services via correlateEndpoints().
func (s *ServiceCache) MergeExternalServiceDelete(service *service.ClusterService) {
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: service.String()})
	id := ServiceID{Name: service.Name, Namespace: service.Namespace}

	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		scopedLog.Debug("Not merging external service. Own cluster")
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	externalEndpoints, ok := s.externalEndpoints[id]
	if ok {
		scopedLog.Debug("Deleting external endpoints")

		delete(externalEndpoints.endpoints, service.Cluster)

		svc, ok := s.services[id]

		endpoints, serviceReady := s.correlateEndpoints(id)

		// Only send event notification if service is shared. External
		// endpoints are still tracked but correlation will not happen
		// until the service is marked as shared.
		if ok && svc.Shared {
			event := ServiceEvent{
				Action:    UpdateService,
				ID:        id,
				Service:   svc,
				Endpoints: endpoints,
			}

			if !serviceReady {
				event.Action = DeleteService
			}

			s.Events <- event
		}
	} else {
		scopedLog.Debug("Received delete event for non-existing endpoints")
	}
}

// DebugStatus implements debug.StatusObject to provide debug status collection
// ability
func (s *ServiceCache) DebugStatus() string {
	s.mutex.RLock()
	str := spew.Sdump(s)
	s.mutex.RUnlock()
	return str
}
