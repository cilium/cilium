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

	"github.com/cilium/cilium/pkg/loadbalancer"
)

type LBMockMap struct {
	BackendByID         map[uint16]struct{}
	ServiceBackendsByID map[uint16][]uint16
}

func NewLBMockMap() *LBMockMap {
	return &LBMockMap{
		BackendByID:         map[uint16]struct{}{},
		ServiceBackendsByID: map[uint16][]uint16{},
	}
}

func (m *LBMockMap) UpsertService(id uint16, ip net.IP, port uint16,
	backendIDs []uint16, prevCount int, ipv6 bool) error {

	if count := len(m.ServiceBackendsByID[id]); prevCount != count {
		return fmt.Errorf("Invalid previous backends count: %d vs %d",
			count, prevCount)
	}

	m.ServiceBackendsByID[id] = backendIDs

	return nil
}

func (m *LBMockMap) DeleteService(addr loadbalancer.L3n4AddrID, backendCount int) error {
	svc, found := m.ServiceBackendsByID[uint16(addr.ID)]
	if !found {
		return fmt.Errorf("Service not found %+v", addr)
	}
	if count := len(svc); count != backendCount {
		return fmt.Errorf("Invalid backends count: %d vs %d",
			count, backendCount)
	}

	delete(m.ServiceBackendsByID, uint16(addr.ID))

	return nil
}

func (m *LBMockMap) AddBackend(id uint16, ip net.IP, port uint16, ipv6 bool) error {
	if _, found := m.BackendByID[id]; found {
		return fmt.Errorf("Backend %d already exists", id)
	}

	m.BackendByID[id] = struct{}{}

	return nil
}

func (m *LBMockMap) DeleteBackendByID(id uint16, ipv6 bool) error {
	if _, found := m.BackendByID[id]; !found {
		return fmt.Errorf("Backend %d does not exist", id)
	}

	delete(m.BackendByID, id)

	return nil
}

func (m *LBMockMap) DumpServiceMapsToUserspaceV2() (loadbalancer.SVCMap, []*loadbalancer.LBSVC, []error) {
	panic("NYI")
}

func (m *LBMockMap) DumpBackendMapsToUserspace() ([]*loadbalancer.LBBackEnd, error) {
	panic("NYI")
}
