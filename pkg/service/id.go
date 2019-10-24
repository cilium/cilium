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

	return serviceIDAlloc.acquireLocalID(l3n4Addr, baseID)
}

// RestoreID restores  previously used service ID
func RestoreID(l3n4Addr loadbalancer.L3n4Addr, baseID uint32) (*loadbalancer.L3n4AddrID, error) {
	log.WithField(logfields.L3n4Addr, logfields.Repr(l3n4Addr)).Debug("Restoring service")

	return serviceIDAlloc.acquireLocalID(l3n4Addr, baseID)
}

// GetID returns the L3n4AddrID that belongs to the given id.
func GetID(id uint32) (*loadbalancer.L3n4AddrID, error) {
	return serviceIDAlloc.getLocalID(id)
}

// DeleteID deletes the L3n4AddrID belonging to the given id from the kvstore.
func DeleteID(id uint32) error {
	log.WithField(logfields.L3n4AddrID, id).Debug("deleting L3n4Addr by ID")

	return serviceIDAlloc.deleteLocalID(id)
}

func setIDSpace(next, max uint32) error {
	return serviceIDAlloc.setLocalIDSpace(next, max)
}

func getMaxServiceID() (uint32, error) {
	return serviceIDAlloc.getLocalMaxID()
}

// AcquireBackendID acquires a new local ID for the given backend.
func AcquireBackendID(l3n4Addr loadbalancer.L3n4Addr) (loadbalancer.BackendID, error) {
	return restoreBackendID(l3n4Addr, 0)
}

// RestoreBackendID tries to restore the given local ID for the given backend.
//
// If ID cannot be restored (ID already taken), returns an error.
func RestoreBackendID(l3n4Addr loadbalancer.L3n4Addr, id loadbalancer.BackendID) error {
	newID, err := restoreBackendID(l3n4Addr, id)
	if err != nil {
		return err
	}

	// TODO(brb) This shouldn't happen (otherwise, there is a bug in the code).
	//           But maybe it makes sense to delete all svc v2 in this case.
	if newID != id {
		DeleteBackendID(newID)
		return fmt.Errorf("restored backend ID for %+v does not match (%d != %d)",
			l3n4Addr, newID, id)
	}

	return nil
}

// DeleteBackendID releases the given backend ID.
// TODO(brb) maybe provide l3n4Addr as an arg for the extra safety.
func DeleteBackendID(id loadbalancer.BackendID) {
	backendIDAlloc.deleteLocalID(uint32(id))
}

// LookupBackendID looks up already allocated backend ID for the given backend
// addr. If such cannot be found, returns an error.
func LookupBackendID(l3n4Addr loadbalancer.L3n4Addr) (loadbalancer.BackendID, error) {
	id, err := backendIDAlloc.lookupLocalID(l3n4Addr)
	return loadbalancer.BackendID(id), err
}

func restoreBackendID(l3n4Addr loadbalancer.L3n4Addr, id loadbalancer.BackendID) (loadbalancer.BackendID, error) {
	l3n4AddrID, err := backendIDAlloc.acquireLocalID(l3n4Addr, uint32(id))
	if err != nil {
		return 0, err
	}
	return loadbalancer.BackendID(l3n4AddrID.ID), nil
}
