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

package lbmap

import (
	"fmt"
	"net"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

type LBMockMap struct {
	BackendByID map[uint16]*lb.LBBackEnd
	ServiceByID map[uint16]*lb.LBSVC
}

func NewLBMockMap() *LBMockMap {
	return &LBMockMap{
		BackendByID: map[uint16]*lb.LBBackEnd{},
		ServiceByID: map[uint16]*lb.LBSVC{},
	}
}

func (m *LBMockMap) UpsertService(id uint16, ip net.IP, port uint16,
	backendIDs []uint16, prevCount int, ipv6 bool) error {

	backends := make([]lb.LBBackEnd, len(backendIDs))
	for i, backendID := range backendIDs {
		b, found := m.BackendByID[backendID]
		if !found {
			return fmt.Errorf("Backend %d not found", id)
		}
		backends[i] = *b
	}

	svc, found := m.ServiceByID[id]
	if !found {
		frontend := lb.NewL3n4AddrID(lb.NONE, ip, port, lb.ID(id))
		svc = &lb.LBSVC{
			Sha256:        frontend.SHA256Sum(),
			FE:            *frontend,
			BackendByHash: nil,
		}
	} else {
		if prevCount != len(svc.BES) {
			return fmt.Errorf("Invalid backends count: %d vs %d", prevCount, len(svc.BES))
		}
	}
	svc.BES = backends

	m.ServiceByID[id] = svc

	return nil
}

func (m *LBMockMap) DeleteService(addr lb.L3n4AddrID, backendCount int) error {
	svc, found := m.ServiceByID[uint16(addr.ID)]
	if !found {
		return fmt.Errorf("Service not found %+v", addr)
	}
	if count := len(svc.BES); count != backendCount {
		return fmt.Errorf("Invalid backends count: %d vs %d",
			count, backendCount)
	}

	delete(m.ServiceByID, uint16(addr.ID))

	return nil
}

func (m *LBMockMap) AddBackend(id uint16, ip net.IP, port uint16, ipv6 bool) error {
	if _, found := m.BackendByID[id]; found {
		return fmt.Errorf("Backend %d already exists", id)
	}

	m.BackendByID[id] = lb.NewLBBackEnd(lb.BackendID(id), lb.NONE, ip, port)

	return nil
}

func (m *LBMockMap) DeleteBackendByID(id uint16, ipv6 bool) error {
	if _, found := m.BackendByID[id]; !found {
		return fmt.Errorf("Backend %d does not exist", id)
	}

	delete(m.BackendByID, id)

	return nil
}

func (m *LBMockMap) DumpServiceMapsToUserspaceV2() ([]*lb.LBSVC, []error) {
	list := make([]*lb.LBSVC, 0, len(m.ServiceByID))
	for _, svc := range m.ServiceByID {
		list = append(list, svc)
	}
	return list, nil
}

func (m *LBMockMap) DumpBackendMapsToUserspace() ([]*lb.LBBackEnd, error) {
	list := make([]*lb.LBBackEnd, 0, len(m.BackendByID))
	for _, backend := range m.BackendByID {
		list = append(list, backend)
	}
	return list, nil
}
