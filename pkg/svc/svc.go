// Copyright 2019 Authors of Cilium
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
package svc

import (
	"fmt"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/service"
)

type Type string

const (
	TypeClusterIP = Type("ClusterIP")
	TypeNodePort  = Type("NodePort")
	TypeOther     = Type("Other")
)

// TODO(brb) move to pkg/counter/strings.go
type StringCounter map[string]int

func (s StringCounter) Add(key string) (changed bool) {
	value, exists := s[key]
	if !exists {
		changed = true
	}
	s[key] = value + 1
	return changed
}

func (s StringCounter) Delete(key string) bool {
	value := s[key]
	if value <= 1 {
		delete(s, key)
		return true
	}
	s[key] = value - 1
	return false
}

type Service struct {
	lock.RWMutex

	svcByHash map[string]*lb.LBSVC
	svcByID   map[lb.ID]*lb.LBSVC

	backendRefCount StringCounter
	backendIDByHash map[string]lb.BackendID
}

func NewService() *Service {
	return &Service{
		svcByHash:       map[string]*lb.LBSVC{},
		svcByID:         map[lb.ID]*lb.LBSVC{},
		backendRefCount: StringCounter{},
		backendIDByHash: map[string]lb.BackendID{},
	}
}

func (s *Service) UpsertService(frontend lb.L3n4AddrID, backends []lb.LBBackEnd, svcType Type) (bool, lb.ID, error) {
	s.Lock()
	defer s.Unlock()

	var err error
	new := false
	ipv6 := frontend.IsIPv6()

	hash := frontend.SHA256Sum()
	svc, found := s.svcByHash[hash]
	if !found {
		new = true
		// TODO(brb) comment why
		backendsCopy := []lb.LBBackEnd{}
		for _, v := range backends {
			backendsCopy = append(backendsCopy, v)
		}

		addrID, err := service.AcquireID(frontend.L3n4Addr, uint32(frontend.ID))
		if err != nil {
			return false, lb.ID(0),
				fmt.Errorf("Unable to allocate service ID %d for %q: %s",
					frontend.ID, frontend, err)
		}
		// TODO(brb) defer ReleaseID
		// TODO(brb) add svc.ID field
		frontend.ID = addrID.ID
		svc = &lb.LBSVC{
			Sha256:        hash,
			FE:            frontend,
			BES:           backendsCopy,
			BackendByHash: map[string]*lb.LBBackEnd{},
			// TODO(brb) Set service type
		}
		s.svcByID[frontend.ID] = svc
		s.svcByHash[hash] = svc
	}

	prevBackendCount := len(svc.BES)
	newBackends, obsoleteBackendIDs, err := s.updateBackendsCacheLocked(svc, backends)
	if err != nil {
		return false, lb.ID(0), err
	}

	for _, b := range newBackends {
		if err := lbmap.AddBackend(uint16(b.ID), b.L3n4Addr.IP, b.L3n4Addr.L4Addr.Port, ipv6); err != nil {
			return false, lb.ID(0), err
		}
	}

	backendIDs := make([]uint16, len(backends))
	for i, b := range backends {
		backendIDs[i] = uint16(b.ID)
	}
	err = lbmap.UpsertService(
		uint16(svc.FE.ID), svc.FE.L3n4Addr.IP, svc.FE.L3n4Addr.L4Addr.Port,
		backendIDs, prevBackendCount,
		ipv6)
	if err != nil {
		return false, lb.ID(0), err
	}

	for _, id := range obsoleteBackendIDs {
		if err := lbmap.DeleteBackendByID(uint16(id), ipv6); err != nil {
			// TODO maybe just log as it's not critical
			return false, lb.ID(0), err
		}
	}

	return new, lb.ID(svc.FE.ID), nil
}

func (s *Service) DeleteServiceByID(id lb.ServiceID) (bool, error) {
	s.Lock()
	defer s.Unlock()

	if svc, found := s.svcByID[lb.ID(id)]; found {
		return true, s.deleteServiceLocked(svc)
	}

	return false, nil
}

func (s *Service) DeleteService(frontend lb.L3n4Addr) (bool, error) {
	s.Lock()
	defer s.Unlock()

	if svc, found := s.svcByHash[frontend.SHA256Sum()]; found {
		return true, s.deleteServiceLocked(svc)
	}

	return false, nil
}

func (s *Service) deleteServiceLocked(svc *lb.LBSVC) error {

	obsoleteBackendIDs := s.deleteBackendsFromCacheLocked(svc)

	if err := lbmap.DeleteService(svc.FE, svc.BES); err != nil {
		return err
	}

	delete(s.svcByHash, svc.Sha256)
	delete(s.svcByID, svc.FE.ID)

	ipv6 := svc.FE.L3n4Addr.IsIPv6()
	for _, id := range obsoleteBackendIDs {
		if err := lbmap.DeleteBackendByID(uint16(id), ipv6); err != nil {
			// TODO maybe just log as it's not critical
			return err
		}
	}

	return nil
}

func (s *Service) updateBackendsCacheLocked(svc *lb.LBSVC, backends []lb.LBBackEnd) ([]lb.LBBackEnd, []lb.BackendID, error) {
	obsoleteBackendIDs := []lb.BackendID{}
	newBackends := []lb.LBBackEnd{}
	backendSet := map[string]struct{}{}

	for i, backend := range backends {
		hash := backend.L3n4Addr.SHA256Sum()
		backendSet[hash] = struct{}{}

		if b, found := svc.BackendByHash[hash]; !found {
			if s.backendRefCount.Add(hash) {
				id, err := service.AcquireBackendID(backend.L3n4Addr)
				if err != nil {
					return nil, nil, fmt.Errorf("Unable to acquire backend ID for %q: %s",
						backend.L3n4Addr, err)
				}
				backends[i].ID = id
				newBackends = append(newBackends, backends[i])
				s.backendIDByHash[hash] = id
			} else {
				backends[i].ID = s.backendIDByHash[hash]
			}
		} else {
			backends[i].ID = b.ID
		}
	}

	for _, backend := range svc.BES {
		hash := backend.L3n4Addr.SHA256Sum()
		if _, found := backendSet[hash]; !found {
			if s.backendRefCount.Delete(hash) {
				service.DeleteBackendID(backend.ID)
				delete(s.backendIDByHash, hash)
				obsoleteBackendIDs = append(obsoleteBackendIDs, backend.ID)
			}

			delete(svc.BackendByHash, hash)
		}
	}

	svc.BES = backends
	return newBackends, obsoleteBackendIDs, nil
}

func (s *Service) deleteBackendsFromCacheLocked(svc *lb.LBSVC) []lb.BackendID {
	obsoleteBackendIDs := []lb.BackendID{}

	for _, backend := range svc.BES {
		hash := backend.L3n4Addr.SHA256Sum()
		if s.backendRefCount.Delete(hash) {
			service.DeleteBackendID(backend.ID)
			obsoleteBackendIDs = append(obsoleteBackendIDs, backend.ID)
		}
	}

	return obsoleteBackendIDs
}
