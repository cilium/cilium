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

package mockmaps

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"
)

type LBMockMap struct {
	BackendByID      map[uint16]*lb.Backend
	ServiceByID      map[uint16]*lb.SVC
	AffinityMatch    lbmap.BackendIDByServiceIDSet
	SourceRanges     lbmap.SourceRangeSetByServiceID
	DummyMaglevTable map[uint16]int // svcID => backends count
}

func NewLBMockMap() *LBMockMap {
	return &LBMockMap{
		BackendByID:      map[uint16]*lb.Backend{},
		ServiceByID:      map[uint16]*lb.SVC{},
		AffinityMatch:    lbmap.BackendIDByServiceIDSet{},
		SourceRanges:     lbmap.SourceRangeSetByServiceID{},
		DummyMaglevTable: map[uint16]int{},
	}
}

func (m *LBMockMap) UpsertService(p *lbmap.UpsertServiceParams) error {
	backendsList := make([]lb.Backend, 0, len(p.Backends))
	for name, backendID := range p.Backends {
		b, found := m.BackendByID[backendID]
		if !found {
			return fmt.Errorf("Backend %s (%d) not found", name, p.ID)
		}
		backendsList = append(backendsList, *b)
	}

	svc, found := m.ServiceByID[p.ID]
	if !found {
		frontend := lb.NewL3n4AddrID(loadbalancer.NewL4Type(p.Protocol), p.IP, p.Port, p.Scope, lb.ID(p.ID))
		svc = &lb.SVC{Frontend: *frontend}
	} else {
		if p.PrevBackendCount != len(svc.Backends) {
			return fmt.Errorf("Invalid backends count: %d vs %d", p.PrevBackendCount, len(svc.Backends))
		}
	}
	svc.Backends = backendsList
	svc.SessionAffinity = p.SessionAffinity
	svc.SessionAffinityTimeoutSec = p.SessionAffinityTimeoutSec
	svc.Type = p.Type

	m.ServiceByID[p.ID] = svc

	return nil
}

func (m *LBMockMap) UpsertMaglevLookupTable(svcID uint16, backends map[string]uint16, ipv6 bool) error {
	m.DummyMaglevTable[svcID] = len(backends)
	return nil
}

func (*LBMockMap) IsMaglevLookupTableRecreated(ipv6 bool) bool {
	return true
}

func (m *LBMockMap) DeleteService(addr lb.L3n4AddrID, backendCount int, maglev bool) error {
	svc, found := m.ServiceByID[uint16(addr.ID)]
	if !found {
		return fmt.Errorf("Service not found %+v", addr)
	}
	if count := len(svc.Backends); count != backendCount {
		return fmt.Errorf("Invalid backends count: %d vs %d",
			count, backendCount)
	}

	delete(m.ServiceByID, uint16(addr.ID))

	return nil
}

func (m *LBMockMap) AddBackend(id uint16, ip net.IP, protocol lb.L4Type, port uint16, ipv6 bool) error {
	if _, found := m.BackendByID[id]; found {
		return fmt.Errorf("Backend %d already exists", id)
	}

	m.BackendByID[id] = lb.NewBackend(lb.BackendID(id), protocol, ip, port)

	return nil
}

func (m *LBMockMap) DeleteBackendByID(id uint16, ipv6 bool) error {
	if _, found := m.BackendByID[id]; !found {
		return fmt.Errorf("Backend %d does not exist", id)
	}

	delete(m.BackendByID, id)

	return nil
}

func (m *LBMockMap) DumpServiceMaps() ([]*lb.SVC, []error) {
	list := make([]*lb.SVC, 0, len(m.ServiceByID))
	for _, svc := range m.ServiceByID {
		list = append(list, svc)
	}
	return list, nil
}

func (m *LBMockMap) DumpBackendMaps() ([]*lb.Backend, error) {
	list := make([]*lb.Backend, 0, len(m.BackendByID))
	for _, backend := range m.BackendByID {
		list = append(list, backend)
	}
	return list, nil
}

func (m *LBMockMap) AddAffinityMatch(revNATID uint16, backendID uint16) error {
	if _, ok := m.AffinityMatch[revNATID]; !ok {
		m.AffinityMatch[revNATID] = map[uint16]struct{}{}
	}
	if _, ok := m.AffinityMatch[revNATID][backendID]; ok {
		return fmt.Errorf("Backend %d already exists in %d affinity map",
			backendID, revNATID)
	}
	m.AffinityMatch[revNATID][backendID] = struct{}{}
	return nil
}

func (m *LBMockMap) DeleteAffinityMatch(revNATID uint16, backendID uint16) error {
	if _, ok := m.AffinityMatch[revNATID]; !ok {
		return fmt.Errorf("Affinity map for %d does not exist", revNATID)
	}
	if _, ok := m.AffinityMatch[revNATID][backendID]; !ok {
		return fmt.Errorf("Backend %d does not exist in %d affinity map",
			backendID, revNATID)
	}
	delete(m.AffinityMatch[revNATID], backendID)
	if len(m.AffinityMatch[revNATID]) == 0 {
		delete(m.AffinityMatch, revNATID)
	}
	return nil
}

func (m *LBMockMap) DumpAffinityMatches() (lbmap.BackendIDByServiceIDSet, error) {
	return m.AffinityMatch, nil
}

func (m *LBMockMap) UpdateSourceRanges(revNATID uint16, prevRanges []*cidr.CIDR,
	ranges []*cidr.CIDR, ipv6 bool) error {

	if len(prevRanges) == 0 {
		m.SourceRanges[revNATID] = []*cidr.CIDR{}
	}
	if len(prevRanges) != len(m.SourceRanges[revNATID]) {
		return fmt.Errorf("Inconsistent view of source ranges")
	}
	m.SourceRanges[revNATID] = ranges

	return nil
}

func (m *LBMockMap) DumpSourceRanges(ipv6 bool) (lbmap.SourceRangeSetByServiceID, error) {
	return m.SourceRanges, nil
}
