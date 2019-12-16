// Copyright 2018-2019 Authors of Cilium
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

package k8s

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"
)

// Endpoints is an abstraction for the Kubernetes endpoints object. Endpoints
// consists of a set of backend IPs in combination with a set of ports and
// protocols. The name of the backend ports must match the names of the
// frontend ports of the corresponding service.
// +k8s:deepcopy-gen=true
type Endpoints struct {
	// Backends is a map containing all backend IPs and ports. The key to
	// the map is the backend IP in string form. The value defines the list
	// of ports for that backend IP, plus an additional optional node name.
	Backends map[string]*Backend
}

// Backend contains all ports and the node name of a given backend
// +k8s:deepcopy-gen=true
type Backend struct {
	Ports    service.PortConfiguration
	NodeName string
}

// DeepEquals returns true if both Backends are identical
func (b *Backend) DeepEquals(o *Backend) bool {
	switch {
	case (b == nil) != (o == nil):
		return false
	case (b == nil) && (o == nil):
		return true
	}

	return b.NodeName == o.NodeName && b.Ports.DeepEquals(o.Ports)
}

// String returns the string representation of an endpoints resource, with
// backends and ports sorted.
func (e *Endpoints) String() string {
	if e == nil {
		return ""
	}

	backends := []string{}
	for ip, be := range e.Backends {
		for _, port := range be.Ports {
			backends = append(backends, fmt.Sprintf("%s/%s", net.JoinHostPort(ip, strconv.Itoa(int(port.Port))), port.Protocol))
		}
	}

	sort.Strings(backends)

	return strings.Join(backends, ",")
}

// newEndpoints returns a new Endpoints
func newEndpoints() *Endpoints {
	return &Endpoints{
		Backends: map[string]*Backend{},
	}
}

// DeepEquals returns true if both endpoints are deep equal.
func (e *Endpoints) DeepEquals(o *Endpoints) bool {
	switch {
	case (e == nil) != (o == nil):
		return false
	case (e == nil) && (o == nil):
		return true
	}

	if len(e.Backends) != len(o.Backends) {
		return false
	}

	for ip1, backend1 := range e.Backends {
		backend2, ok := o.Backends[ip1]
		if !ok {
			return false
		}

		if !backend1.DeepEquals(backend2) {
			return false
		}
	}

	return true
}

// CIDRPrefixes returns the endpoint's backends as a slice of IPNets.
func (e *Endpoints) CIDRPrefixes() ([]*net.IPNet, error) {
	prefixes := make([]string, len(e.Backends))
	index := 0
	for ip := range e.Backends {
		prefixes[index] = ip
		index++
	}

	valid, invalid := ip.ParseCIDRs(prefixes)
	if len(invalid) > 0 {
		return nil, fmt.Errorf("invalid IPs specified as backends: %+v", invalid)
	}

	return valid, nil
}

// ParseEndpointsID parses a Kubernetes endpoints and returns the ServiceID
func ParseEndpointsID(svc *types.Endpoints) ServiceID {
	return ServiceID{
		Name:      svc.ObjectMeta.Name,
		Namespace: svc.ObjectMeta.Namespace,
	}
}

// ParseEndpoints parses a Kubernetes Endpoints resource
func ParseEndpoints(ep *types.Endpoints) (ServiceID, *Endpoints) {
	endpoints := newEndpoints()

	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			backend, ok := endpoints.Backends[addr.IP]
			if !ok {
				backend = &Backend{Ports: service.PortConfiguration{}}
				endpoints.Backends[addr.IP] = backend
			}

			if addr.NodeName != nil {
				backend.NodeName = *addr.NodeName
			}

			for _, port := range sub.Ports {
				lbPort := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
				backend.Ports[port.Name] = lbPort
			}
		}
	}

	return ParseEndpointsID(ep), endpoints
}

// externalEndpoints is the collection of external endpoints in all remote
// clusters. The map key is the name of the remote cluster.
type externalEndpoints struct {
	endpoints map[string]*Endpoints
}

// newExternalEndpoints returns a new ExternalEndpoints
func newExternalEndpoints() externalEndpoints {
	return externalEndpoints{
		endpoints: map[string]*Endpoints{},
	}
}
