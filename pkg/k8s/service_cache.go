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

package k8s

import (
	"net"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/versioned"

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
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

	// Endpoints is the endpoints structured correlated with the service
	Endpoints *Endpoints
}

// ServiceCache is a list of services and ingresses correlated with the
// matching endpoints. The Events member will receive events as services and
// ingresses
type ServiceCache struct {
	mutex     lock.RWMutex
	services  map[ServiceID]*Service
	endpoints map[ServiceID]*Endpoints
	ingresses map[ServiceID]*Service

	Events chan ServiceEvent
}

// NewServiceCache returns a new ServiceCache
func NewServiceCache() ServiceCache {
	return ServiceCache{
		services:  map[ServiceID]*Service{},
		endpoints: map[ServiceID]*Endpoints{},
		ingresses: map[ServiceID]*Service{},
		Events:    make(chan ServiceEvent, 128),
	}
}

// UpdateService parses a Kubernetes service and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes service could not
// be parsed and a bool to indicate whether the service was changed in the
// cache or not.
func (s *ServiceCache) UpdateService(k8sSvc *v1.Service) ServiceID {
	svcID, newService := ParseService(k8sSvc)
	if newService == nil {
		return svcID
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if oldService, ok := s.services[svcID]; ok {
		if oldService.DeepEquals(newService) {
			return svcID
		}
	}

	s.services[svcID] = newService

	// Check if the corresponding Endpoints resource is already available
	endpoints, ok := s.endpoints[svcID]
	if ok {
		s.Events <- ServiceEvent{
			Action:    UpdateService,
			ID:        svcID,
			Service:   newService,
			Endpoints: endpoints,
		}
	}

	return svcID
}

// DeleteService parses a Kubernetes service and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteService(k8sSvc *v1.Service) {
	svcID := ParseServiceID(k8sSvc)

	s.mutex.Lock()
	oldService, serviceOK := s.services[svcID]
	endpoints, endpointsOK := s.endpoints[svcID]
	delete(s.services, svcID)
	s.mutex.Unlock()

	if serviceOK && endpointsOK {
		s.Events <- ServiceEvent{
			Action:    DeleteService,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
		}
	}
}

// ListMissingServices returns a map of all services listed in requiredServices
// that are not found in the cache.
func (s *ServiceCache) ListMissingServices(requiredServices versioned.Map) versioned.Map {
	missing := versioned.NewMap()

	s.mutex.RLock()
	for uuid, svcObj := range requiredServices {
		neededSvc := svcObj.Data.(*v1.Service)
		id := ParseServiceID(neededSvc)

		existingService, ok := s.services[id]
		if !ok {
			missing.Add(uuid, svcObj)
			continue
		}

		_, newService := ParseService(neededSvc)
		if !existingService.DeepEquals(newService) {
			missing.Add(uuid, svcObj)
		}
	}
	s.mutex.RUnlock()

	return missing
}

// UpdateEndpoints parses a Kubernetes endpoints and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes endpoints could not
// be parsed and a bool to indicate whether the endpoints was changed in the
// cache or not.
func (s *ServiceCache) UpdateEndpoints(k8sEndpoints *v1.Endpoints) (ServiceID, *Endpoints) {
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
	if ok {
		s.Events <- ServiceEvent{
			Action:    UpdateService,
			ID:        svcID,
			Service:   service,
			Endpoints: newEndpoints,
		}
	}

	return svcID, newEndpoints
}

// DeleteEndpoints parses a Kubernetes endpoints and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteEndpoints(k8sEndpoints *v1.Endpoints) ServiceID {
	svcID := ParseEndpointsID(k8sEndpoints)

	s.mutex.Lock()
	service, serviceOK := s.services[svcID]
	endpoints, endpointsOK := s.endpoints[svcID]
	delete(s.endpoints, svcID)
	s.mutex.Unlock()

	if serviceOK && endpointsOK {
		s.Events <- ServiceEvent{
			Action:    DeleteService,
			ID:        svcID,
			Service:   service,
			Endpoints: endpoints,
		}
	}

	return svcID
}

// ListMissingEndpoints returns the list of required endpoints that is not in
// the cache
func (s *ServiceCache) ListMissingEndpoints(requiredEndpoints versioned.Map) versioned.Map {
	type parsedEndpoints struct {
		id        ServiceID
		endpoints *Endpoints
		uuid      versioned.UUID
		object    versioned.Object
	}

	// parse endpoints first to avoid holding the loadBalancer mutex
	parsed := make([]parsedEndpoints, 0, len(requiredEndpoints))
	for uuid, endpointsObj := range requiredEndpoints {
		id, endpoints := ParseEndpoints(endpointsObj.Data.(*v1.Endpoints))
		parsed = append(parsed, parsedEndpoints{
			id:        id,
			endpoints: endpoints,
			uuid:      uuid,
			object:    endpointsObj,
		})
	}

	missing := versioned.NewMap()

	s.mutex.RLock()
	for _, p := range parsed {
		existingEndpoint, ok := s.endpoints[p.id]
		if !ok {
			missing.Add(p.uuid, p.object)
			continue
		}
		if !p.endpoints.DeepEquals(existingEndpoint) {
			missing.Add(p.uuid, p.object)
		}
	}
	s.mutex.RUnlock()

	return missing
}

// UpdateIngress parses a Kubernetes ingress and adds or updates it in the
// ServiceCache.
func (s *ServiceCache) UpdateIngress(ingress *v1beta1.Ingress, host net.IP) (ServiceID, error) {
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
func (s *ServiceCache) DeleteIngress(ingress *v1beta1.Ingress) {
	svcID := ParseIngressID(ingress)

	s.mutex.Lock()
	oldService, ok := s.ingresses[svcID]
	endpoints, _ := s.endpoints[svcID]
	delete(s.ingresses, svcID)
	s.mutex.Unlock()

	if ok {
		s.Events <- ServiceEvent{
			Action:    DeleteIngress,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
		}
	}
}

// ListMissingIngresses returns a map of all ingress listed in required that
// are not found in the cache.
func (s *ServiceCache) ListMissingIngresses(required versioned.Map, host net.IP) versioned.Map {
	missing := versioned.NewMap()

	s.mutex.RLock()
	for uuid, svcObj := range required {
		neededSvc := svcObj.Data.(*v1beta1.Ingress)
		id := ParseIngressID(neededSvc)

		existingService, ok := s.ingresses[id]
		if !ok {
			missing.Add(uuid, svcObj)
			continue
		}

		_, newService, err := ParseIngress(neededSvc, host)
		if err != nil || !existingService.DeepEquals(newService) {
			missing.Add(uuid, svcObj)
		}
	}
	s.mutex.RUnlock()

	return missing
}

// UniqueServiceFrontends returns all services known to the service cache as a map, indexed by
// the string representation of a loadbalancer.L3n4Addr
func (s *ServiceCache) UniqueServiceFrontends() map[string]struct{} {
	uniqueFrontends := make(map[string]struct{})

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
	}

	return uniqueFrontends
}
