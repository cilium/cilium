// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
)

// LocalEndpointStore tracks the mapping between a given endpoint IP and the actual local endpoint.
type LocalEndpointStore struct {
	// mutex protects accesses to the configuration resources below.
	mutex lock.RWMutex

	// networkPolicyEndpoints maps endpoint IP to the info on the local endpoint.
	// mutex must be held when accessing this.
	networkPolicyEndpoints map[string]endpoint.EndpointUpdater
}

// getLocalEndpoint returns the endpoint info for the local endpoint on which
// the network policy of the given name if enforced, or nil if not found.
func (s *LocalEndpointStore) getLocalEndpoint(endpointIP string) endpoint.EndpointUpdater {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.networkPolicyEndpoints[endpointIP]
}

// setLocalEndpoint maps the given IP to the local endpoint.
func (s *LocalEndpointStore) setLocalEndpoint(endpointIP string, ep endpoint.EndpointUpdater) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.networkPolicyEndpoints[endpointIP] = ep
}

// removeLocalEndpoint delete the mapping for the given endpoint IP
func (s *LocalEndpointStore) removeLocalEndpoint(endpointIP string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.networkPolicyEndpoints, endpointIP)
}
