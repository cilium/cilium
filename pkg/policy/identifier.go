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

// Endpoint refers to any structure which has the following properties:
// * a node-local ID stored as a uint16
// * a security identity
// * a means of incrementing its policy revision
// * a means of checking if it represents a node or a pod.
type Endpoint interface {
	GetID16() uint16
	GetSecurityIdentity() (*identity.Identity, error)
	PolicyRevisionBumpEvent(rev uint64)
	IsHost() bool
}

// EndpointSet is used to be able to group together a given set of Endpoints
// that need to have a specific operation performed upon them (e.g., policy
// revision updates).
type EndpointSet struct {
	mutex     lock.RWMutex
	endpoints map[Endpoint]struct{}
}

// NewEndpointSet returns an EndpointSet with the given Endpoints map
func NewEndpointSet(m map[Endpoint]struct{}) *EndpointSet {
	if m != nil {
		return &EndpointSet{
			endpoints: m,
		}
	}
	return &EndpointSet{
		endpoints: map[Endpoint]struct{}{},
	}
}

// ForEachGo runs epFunc asynchronously inside a go routine for each endpoint in
// the EndpointSet. It signals to the provided WaitGroup when epFunc has been
// executed for each endpoint.
func (e *EndpointSet) ForEachGo(wg *sync.WaitGroup, epFunc func(epp Endpoint)) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

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
func (e *EndpointSet) Len() (nElem int) {
	e.mutex.RLock()
	nElem = len(e.endpoints)
	e.mutex.RUnlock()
	return
}
