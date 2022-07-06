// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mockmaps

import (
	"fmt"

	"github.com/cilium/cilium/pkg/cidr"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"
)

type LBMockMap struct {
	BackendByID            map[lb.BackendID]*lb.Backend
	ServiceByID            map[uint16]*lb.SVC
	AffinityMatch          lbmap.BackendIDByServiceIDSet
	SourceRanges           lbmap.SourceRangeSetByServiceID
	DummyMaglevTable       map[uint16]int // svcID => backends count
	SvcActiveBackendsCount map[uint16]int
}

func NewLBMockMap() *LBMockMap {
	return &LBMockMap{
		BackendByID:            map[lb.BackendID]*lb.Backend{},
		ServiceByID:            map[uint16]*lb.SVC{},
		AffinityMatch:          lbmap.BackendIDByServiceIDSet{},
		SourceRanges:           lbmap.SourceRangeSetByServiceID{},
		DummyMaglevTable:       map[uint16]int{},
		SvcActiveBackendsCount: map[uint16]int{},
	}
}

func (m *LBMockMap) UpsertService(p *lbmap.UpsertServiceParams) error {
	backendIDs := lbmap.GetOrderedBackends(p)
	backendsList := make([]*lb.Backend, 0, len(backendIDs))
	for _, backendID := range backendIDs {
		b, found := m.BackendByID[backendID]
		if !found {
			return fmt.Errorf("backend %d not found", p.ID)
		}
		backendsList = append(backendsList, b)
	}
	backends := p.ActiveBackends
	if len(p.PreferredBackends) > 0 {
		backends = p.PreferredBackends
	}
	if p.UseMaglev && len(backends) != 0 {
		if err := m.UpsertMaglevLookupTable(p.ID, backends, p.IPv6); err != nil {
			return err
		}
	}
	svc, found := m.ServiceByID[p.ID]
	if !found {
		frontend := lb.NewL3n4AddrID(lb.NONE, p.IP, p.Port, p.Scope, lb.ID(p.ID))
		svc = &lb.SVC{Frontend: *frontend}
	} else {
		if p.PrevBackendsCount != len(svc.Backends) {
			return fmt.Errorf("Invalid backends count: %d vs %d", p.PrevBackendsCount, len(svc.Backends))
		}
	}
	svc.Backends = backendsList
	svc.SessionAffinity = p.SessionAffinity
	svc.SessionAffinityTimeoutSec = p.SessionAffinityTimeoutSec
	svc.Type = p.Type

	m.ServiceByID[p.ID] = svc
	m.SvcActiveBackendsCount[p.ID] = len(p.ActiveBackends)

	return nil
}

func (m *LBMockMap) UpsertMaglevLookupTable(svcID uint16, backends map[string]lb.BackendID, ipv6 bool) error {
	m.DummyMaglevTable[svcID] = len(backends)
	return nil
}

func (*LBMockMap) IsMaglevLookupTableRecreated(ipv6 bool) bool {
	return true
}

func (m *LBMockMap) DeleteService(addr lb.L3n4AddrID, backendCount int, maglev bool, natPolicy lb.SVCNatPolicy) error {
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

func (m *LBMockMap) AddBackend(b *lb.Backend, ipv6 bool) error {
	id := b.ID
	ip := b.IP
	port := b.Port

	// Backends can be added to both v4 and v6 lb maps (when nat64 policies
	// are enabled).
	if _, found := m.BackendByID[id]; found && !b.L3n4Addr.IsIPv6() && !ipv6 {
		return fmt.Errorf("Backend %d already exists", id)
	}

	be := lb.NewBackendWithState(id, b.Protocol, ip, port, b.State, false)
	m.BackendByID[id] = be

	return nil
}

func (m *LBMockMap) UpdateBackendWithState(b *lb.Backend) error {
	id := b.ID

	be, found := m.BackendByID[id]
	if !found {
		return fmt.Errorf("update failed : backend %d doesn't exist", id)
	}
	if b.ID != be.ID || b.Port != be.Port || !b.IP.Equal(be.IP) {
		return fmt.Errorf("backend in the map  %+v doesn't match %+v: only backend"+
			"state can be updated", be.String(), b.String())
	}
	be.State = b.State

	return nil
}

func (m *LBMockMap) DeleteBackendByID(id lb.BackendID) error {
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
		backend.RestoredFromDatapath = true
		list = append(list, backend)
	}
	return list, nil
}

func (m *LBMockMap) AddAffinityMatch(revNATID uint16, backendID lb.BackendID) error {
	if _, ok := m.AffinityMatch[revNATID]; !ok {
		m.AffinityMatch[revNATID] = map[lb.BackendID]struct{}{}
	}
	if _, ok := m.AffinityMatch[revNATID][backendID]; ok {
		return fmt.Errorf("Backend %d already exists in %d affinity map",
			backendID, revNATID)
	}
	m.AffinityMatch[revNATID][backendID] = struct{}{}
	return nil
}

func (m *LBMockMap) DeleteAffinityMatch(revNATID uint16, backendID lb.BackendID) error {
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
