// Copyright 2019 Authors of Hubble
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

package v1

import (
	"net"
)

// EndpointsHandler defines an interface for interacting with Cilium endpoints.
type EndpointsHandler interface {
	SyncEndpoints([]*Endpoint)
	UpdateEndpoint(*Endpoint)
	FindEPs(epID uint64, ns, pod string) []Endpoint
	GetEndpoint(ip net.IP) (endpoint *Endpoint, ok bool)
	DeleteEndpoint(*Endpoint)
	GetEndpointByContainerID(id string) (*Endpoint, bool)
	GetEndpointByPodName(namespace string, name string) (*Endpoint, bool)
}

// EqualsByID compares if the receiver's endpoint has the same ID, PodName and
// PodNamespace.
func (e *Endpoint) EqualsByID(o *Endpoint) bool {
	if o == nil {
		return false
	}
	return (e.ID == o.ID && e.PodName == "" && e.PodNamespace == "") ||
		e.ID == o.ID &&
			e.PodName == o.PodName &&
			e.PodNamespace == o.PodNamespace
}

// DeepCopy returns a deep copy of this endpoint.
func (e *Endpoint) DeepCopy() *Endpoint {
	result := *e
	if e.ContainerIDs != nil {
		result.ContainerIDs = make([]string, len(e.ContainerIDs))
		copy(result.ContainerIDs, e.ContainerIDs)
	}
	if e.IPv4 != nil {
		result.IPv4 = make(net.IP, len(e.IPv4))
		copy(result.IPv4, e.IPv4)
	}
	if e.IPv6 != nil {
		result.IPv6 = make(net.IP, len(e.IPv6))
		copy(result.IPv6, e.IPv6)
	}
	if e.Labels != nil {
		result.Labels = make([]string, len(e.Labels))
		copy(result.Labels, e.Labels)
	}
	return &result
}

// SyncEndpoints adds the given list of endpoints to the internal endpoint
// slice.
func (es *Endpoints) SyncEndpoints(newEps []*Endpoint) {
	if len(newEps) == 0 {
		return
	}
	es.mutex.Lock()
	defer es.mutex.Unlock()
	// Add the endpoint to the list of endpoints.
	for _, updatedEp := range newEps {
		es.updateEndpoint(updatedEp)
	}
	// some endpoints were deleted, remove them
	if len(es.eps) != len(newEps) {
		for _, ep := range es.eps {
			found := false
			for _, newEp := range newEps {
				if newEp.EqualsByID(ep) {
					found = true
					break
				}
			}
			if !found {
				es.deleteEndpoint(ep)
			}
		}
	}
}

// FindEPs returns all the EPs that have the given epID or the given namespace
// or the given podName (running in the given namespace).
func (es *Endpoints) FindEPs(epID uint64, namespace string, podName string) []Endpoint {
	var eps []Endpoint
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	for _, ep := range es.eps {
		// If is the endpoint ID we are looking for
		if (epID != 0 && ep.ID == epID) ||
			// The pod name is the one we are looking for
			(podName != "" && (ep.PodName == podName && ep.PodNamespace == namespace)) ||
			// The pod namespace is in the same namespace we are looking for
			(podName == "" && ep.PodNamespace == namespace) {

			eps = append(eps, *ep)
		}
	}

	return eps
}

// setFrom sets all fields from the given endpoint 'o' in receiver's endpoint.
func (e *Endpoint) setFrom(o *Endpoint) {
	if o.ContainerIDs != nil {
		e.ContainerIDs = o.ContainerIDs
	}
	if o.ID != 0 {
		e.ID = o.ID
	}
	if o.IPv4 != nil {
		e.IPv4 = o.IPv4
	}
	if o.IPv6 != nil {
		e.IPv6 = o.IPv6
	}
	if len(o.Labels) != 0 {
		e.Labels = o.Labels
	}
	if o.PodName != "" {
		e.PodName = o.PodName
	}
	if o.PodNamespace != "" {
		e.PodNamespace = o.PodNamespace
	}
}

func (es *Endpoints) updateEndpoint(updateEp *Endpoint) {
	for _, ep := range es.eps {
		// Update endpoint if the ID is the same *and* the podName and
		// podNamespace do not exist, otherwise check if the given updateEp
		// equals to ep.
		if ep.EqualsByID(updateEp) {
			ep.setFrom(updateEp)
			return
		}
	}
	// If we haven't found it, then we need to add it to the list of
	// endpoints
	es.eps = append(es.eps, updateEp)
}

// UpdateEndpoint updates the given endpoint if already exists in the slice of
// endpoints. If the endpoint does not exists, it is appended to the slice of
// endpoints.
func (es *Endpoints) UpdateEndpoint(updateEp *Endpoint) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	es.updateEndpoint(updateEp)
}

// GetEndpoint returns the endpoint that has the given ip.
func (es *Endpoints) GetEndpoint(ip net.IP) (endpoint *Endpoint, ok bool) {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	for _, ep := range es.eps {
		if ep.IPv4.Equal(ip) || ep.IPv6.Equal(ip) {
			return ep.DeepCopy(), true
		}
	}
	return
}

// DeleteEndpoint deletes the given endpoint if present in the endpoints slice.
func (es *Endpoints) DeleteEndpoint(del *Endpoint) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	es.deleteEndpoint(del)
}

func (es *Endpoints) deleteEndpoint(del *Endpoint) {
	for i, ep := range es.eps {
		if ep.EqualsByID(del) {
			// deleting without preserving order avoids doing a new allocation
			es.eps[i] = es.eps[len(es.eps)-1]
			es.eps[len(es.eps)-1] = nil // avoid memory leak
			es.eps = es.eps[:len(es.eps)-1]
			break
		}
	}
}

// GetEndpointInfo returns the endpoint info that has the given ip.
func (es *Endpoints) GetEndpointInfo(ip net.IP) (endpoint EndpointInfo, ok bool) {
	return es.GetEndpoint(ip)
}

// GetEndpointByContainerID returns the endpoint that has the given container ID.
func (es *Endpoints) GetEndpointByContainerID(id string) (*Endpoint, bool) {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	for _, ep := range es.eps {
		for _, containerID := range ep.ContainerIDs {
			if id == containerID {
				return ep.DeepCopy(), true
			}
		}
	}
	return nil, false
}

// GetEndpointByPodName returns the endpoint with the given pod name.
func (es *Endpoints) GetEndpointByPodName(namespace string, name string) (*Endpoint, bool) {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	for _, ep := range es.eps {
		if ep.PodNamespace == namespace && ep.PodName == name {
			return ep.DeepCopy(), true
		}
	}
	return nil, false
}
