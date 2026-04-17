// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
)

// LocalEndpointStore tracks the mapping between a given endpoint IP and the local endpoint.
type LocalEndpointStore struct {
	// mutex protects accesses to the configuration resources below.
	mutex lock.RWMutex

	// networkPolicyEndpoints maps endpoint IP to the info on the local endpoint.
	// mutex must be held when accessing this.
	// endpoint.EndpointUpdater interface must be stable for the lifetime of the endpoint.
	networkPolicyEndpoints map[string]endpoint.EndpointUpdater
}

// endpointInfo is the map key/value pair used to report conflicts
// Empty 'ip' strings or nil 'ep' values are not used.
type endpointInfo struct {
	policyName string
	ep         endpoint.EndpointInfoSource
}

func (d endpointInfo) String() string {
	return fmt.Sprintf("PolicyName: %s, EndpointID: %d", d.policyName, d.ep.GetID())
}

// getLocalEndpoint returns the endpoint info for the local endpoint on which
// the network policy of the given name if enforced, or nil if not found.
func (s *LocalEndpointStore) getLocalEndpoint(name string) endpoint.EndpointUpdater {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.networkPolicyEndpoints[name]
}

// setLocalEndpoint maps endpoint's policy names to the local endpoint.
// 'ep' must not be nil. Returns any conflicts found, nil for none.
func (s *LocalEndpointStore) setLocalEndpoint(ep endpoint.EndpointUpdater) []endpointInfo {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var conflicts []endpointInfo
	for _, name := range ep.GetPolicyNames() {
		foundEP := s.networkPolicyEndpoints[name]
		// 'ep' is assumed to be stable for the lifetime of the endpoint, so
		// interface inequality indicates a conflict.
		if foundEP != nil && foundEP != ep {
			conflicts = append(conflicts, endpointInfo{policyName: name, ep: foundEP})
		}
		s.networkPolicyEndpoints[name] = ep
	}
	if len(conflicts) > 0 {
		// remove all entries for the conflicting endpoints
		for name, existingEP := range s.networkPolicyEndpoints {
			for _, conflict := range conflicts {
				if existingEP == conflict.ep {
					delete(s.networkPolicyEndpoints, name)
				}
			}
		}
	}
	return conflicts
}

// removeLocalEndpoint deletes the IP mappings for the given endpoint.
// Returns any conflicts found, nil for none.
func (s *LocalEndpointStore) removeLocalEndpoint(ep endpoint.EndpointInfoSource) {
	names := ep.GetPolicyNames()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	deleteCount := 0
	for _, name := range names {
		foundEP, found := s.networkPolicyEndpoints[name]
		// 'ep' is assumed to be stable for the lifetime of the endpoint.
		if found && foundEP == ep {
			deleteCount++
			delete(s.networkPolicyEndpoints, name)
		}
	}

	if deleteCount < len(names) {
		// One or more IPs was not deleted, make sure this endpoint is removed by scanning
		// the map.
		for name, existingEP := range s.networkPolicyEndpoints {
			if existingEP == ep {
				delete(s.networkPolicyEndpoints, name)
			}
		}
	}
}
