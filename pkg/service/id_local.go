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

package service

import (
	"fmt"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	// mutex protects servicesID, services, nextID and maxID
	mutex lock.RWMutex

	// servicesID is a map of all services indexed by service ID
	servicesID = map[uint32]*types.L3n4AddrID{}

	// services is a map of all services indexed by L3n4Addr.StringID()
	services = map[string]uint32{}

	// nextID is the next service ID to attempt to allocate
	nextID = common.FirstFreeServiceID

	// maxID is the maximum service ID available for allocation
	maxID = common.MaxSetOfServiceID
)

func newServiceID(svc types.L3n4Addr, id uint32) *types.L3n4AddrID {
	return &types.L3n4AddrID{
		L3n4Addr: svc,
		ID:       types.ServiceID(id),
	}
}

func addServiceID(svc types.L3n4Addr, id uint32) *types.L3n4AddrID {
	svcID := newServiceID(svc, id)
	servicesID[id] = svcID
	services[svc.StringID()] = id

	return svcID
}

func acquireLocalID(svc types.L3n4Addr, desiredID uint32) (*types.L3n4AddrID, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if svcID, ok := services[svc.StringID()]; ok {
		if svc, ok := servicesID[svcID]; ok {
			return svc, nil
		}
	}

	if desiredID != 0 {
		if _, ok := servicesID[desiredID]; !ok {
			return addServiceID(svc, desiredID), nil
		}
	}

	startingID := nextID
	rollover := false
	for {
		if nextID == startingID && rollover {
			break
		} else if nextID == maxID {
			nextID = common.FirstFreeServiceID
			rollover = true
		}

		if _, ok := servicesID[nextID]; !ok {
			svcID := addServiceID(svc, nextID)
			nextID++
			return svcID, nil
		}

		nextID++
	}

	return nil, fmt.Errorf("no service ID available")
}

func getLocalID(id uint32) (*types.L3n4AddrID, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	if svc, ok := servicesID[id]; ok {
		return svc, nil
	}

	return nil, nil
}

func deleteLocalID(id uint32) error {
	mutex.Lock()
	defer mutex.Unlock()

	if svc, ok := servicesID[id]; ok {
		delete(servicesID, id)
		delete(services, svc.StringID())
	}

	return nil
}

func setLocalIDSpace(next, max uint32) error {
	mutex.Lock()
	nextID = next
	maxID = max
	mutex.Unlock()

	return nil
}

func getLocalMaxServiceID() (uint32, error) {
	mutex.RLock()
	defer mutex.RUnlock()
	return nextID, nil
}

func resetLocalID() {
	mutex.Lock()
	servicesID = map[uint32]*types.L3n4AddrID{}
	services = map[string]uint32{}
	nextID = common.FirstFreeServiceID
	maxID = common.MaxSetOfServiceID
	mutex.Unlock()
}
