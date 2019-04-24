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

package policy

import (
	"sync"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
)

// IDSet is a wrapper type around a set of unsigned 16-bit integers, with
// a mutex for protecting access.
type IDSet struct {
	Mutex lock.RWMutex
	IDs   map[uint16]struct{}
}

// NewIDSet returns a new instance of an IDSet.
func NewIDSet() *IDSet {
	return &IDSet{
		IDs: map[uint16]struct{}{},
	}
}

// Endpoint refers to any structure which has the following properties:
// * a node-local ID stored as a uint16
// * a security identity
// * a means of incrementing its policy revision
type Endpoint interface {
	GetID16() uint16
	RLockAlive() error
	RUnlock()
	GetSecurityIdentity() *identity.Identity
	PolicyRevisionBumpEvent(rev uint64)
}

// EndpointSet is used to be able to group together a given set of Endpoints
// that need to have a specific operation performed upon them (e.g., policy
// revision updates).
type EndpointSet struct {
	mutex     lock.RWMutex
	endpoints map[Endpoint]struct{}
}

// NewEndpointSet returns an EndpointSet with the Endpoints map allocated with
// the specified capacity.
func NewEndpointSet(capacity int) *EndpointSet {
	return &EndpointSet{
		endpoints: make(map[Endpoint]struct{}, capacity),
	}
}

// ForEach runs epFunc asynchronously for all endpoints in the EndpointSet. It
// signals to the provided WaitGroup when epFunc has been executed for each
// endpoint.
func (e *EndpointSet) ForEach(wg *sync.WaitGroup, epFunc func(epp Endpoint)) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	wg.Add(len(e.endpoints))

	for ep := range e.endpoints {
		go func(eppp Endpoint) {
			epFunc(eppp)
			wg.Done()
		}(ep)
	}
}

// Delete removes ep from the EndpointSet.
func (e *EndpointSet) Delete(ep Endpoint) {
	e.mutex.Lock()
	delete(e.endpoints, ep)
	e.mutex.Unlock()
}

// Insert adds ep to the EndpointSet.
func (e *EndpointSet) Insert(ep Endpoint) {
	e.mutex.Lock()
	e.endpoints[ep] = struct{}{}
	e.mutex.Unlock()
}

// Len returns the number of elements in the EndpointSet.
func (e *EndpointSet) Len() int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return len(e.endpoints)
}
