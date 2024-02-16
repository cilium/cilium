// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
// * a set of labels
// * a kubernetes namespace
type Endpoint interface {
	GetID16() uint16
	GetSecurityIdentity() (*identity.Identity, error)
	PolicyRevisionBumpEvent(rev uint64)
	IsHost() bool
	GetOpLabels() []string
	GetK8sNamespace() string
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

// ForEachGo runs epFunc asynchronously inside a goroutine for each endpoint in
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
