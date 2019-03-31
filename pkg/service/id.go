// Copyright 2016-2018 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// AcquireID acquires a service ID
func AcquireID(l3n4Addr loadbalancer.L3n4Addr, baseID uint32) (*loadbalancer.L3n4AddrID, error) {
	log.WithField(logfields.L3n4Addr, logfields.Repr(l3n4Addr)).Debug("Resolving service")

	if enableGlobalServiceIDs {
		return acquireGlobalID(l3n4Addr, baseID)
	}

	return serviceIDAlloc.acquireLocalID(l3n4Addr, baseID)
}

// RestoreID restores  previously used service ID
func RestoreID(l3n4Addr loadbalancer.L3n4Addr, baseID uint32) (*loadbalancer.L3n4AddrID, error) {
	log.WithField(logfields.L3n4Addr, logfields.Repr(l3n4Addr)).Debug("Restoring service")

	if enableGlobalServiceIDs {
		// global service IDs do not require to pass in the existing
		// service ID. The global state will guarantee that the same
		// service will resolve to the same service ID again.
		return acquireGlobalID(l3n4Addr, 0)
	}

	return serviceIDAlloc.acquireLocalID(l3n4Addr, baseID)
}

// GetID returns the L3n4AddrID that belongs to the given id.
func GetID(id uint32) (*loadbalancer.L3n4AddrID, error) {
	if enableGlobalServiceIDs {
		return getGlobalID(id)
	}

	return serviceIDAlloc.getLocalID(id)
}

// DeleteID deletes the L3n4AddrID belonging to the given id from the kvstore.
func DeleteID(id uint32) error {
	log.WithField(logfields.L3n4AddrID, id).Debug("deleting L3n4Addr by ID")

	if enableGlobalServiceIDs {
		return deleteGlobalID(id)
	}

	return serviceIDAlloc.deleteLocalID(id)
}

func setIDSpace(next, max uint32) error {
	if enableGlobalServiceIDs {
		return setGlobalIDSpace(next, max)
	}

	return serviceIDAlloc.setLocalIDSpace(next, max)
}

func getMaxServiceID() (uint32, error) {
	if enableGlobalServiceIDs {
		return getGlobalMaxServiceID()
	}

	return serviceIDAlloc.getLocalMaxServiceID()
}

// AcquireBackendID acquires a new local ID for the given backend.
func AcquireBackendID(l3n4Addr loadbalancer.L3n4Addr) (uint16, error) {
	return restoreBackendID(l3n4Addr, 0)
}

// RestoreBackendID tries to restore the given local ID for the given backend.
//
// If ID cannot be restored (ID already taken), returns an error.
func RestoreBackendID(l3n4Addr loadbalancer.L3n4Addr, id uint16) error {
	newID, err := restoreBackendID(l3n4Addr, id)
	if err != nil {
		return err
	}

	// TODO(brb) This shouldn't happen (otherwise, there is a bug in the code).
	//           But maybe it makes sense to delete all svc v2 in this case.
	if newID != id {
		DeleteBackendID(newID)
		return fmt.Errorf("Restored backend ID for %+v does not match (%d != %d)",
			l3n4Addr, newID, id)
	}

	return nil
}

// DeleteBackendID releases the given backend ID.
// TODO(brb) maybe provide l3n4Addr as an arg for the extra safety.
func DeleteBackendID(id uint16) {
	backendIDAlloc.deleteLocalID(uint32(id))
}

func restoreBackendID(l3n4Addr loadbalancer.L3n4Addr, id uint16) (uint16, error) {
	l3n4AddrID, err := backendIDAlloc.acquireLocalID(l3n4Addr, uint32(id))
	if err != nil {
		return 0, err
	}
	return uint16(l3n4AddrID.ID), nil
}
