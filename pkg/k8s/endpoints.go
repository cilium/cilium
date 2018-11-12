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

package k8s

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"

	"k8s.io/api/core/v1"
)

// Endpoints is an abstraction for the kubernetes endpoints object. Each
// service is composed by a set of backend IPs (BEIPs) and a map of Ports
// (Ports). Each k8s endpoint present in BEIPs share the same list of Ports
// open.
type Endpoints struct {
	Backends map[string]service.PortConfiguration
}

// String returns the string representation of an endpoints resource, with
// backends and ports sorted.
func (e *Endpoints) String() string {
	backends := []string{}
	for ip, ports := range e.Backends {
		for _, port := range ports {
			backends = append(backends, fmt.Sprintf("%s:%d/%s", ip, port.Port, port.Protocol))
		}
	}

	sort.Strings(backends)

	return strings.Join(backends, ",")
}

// newEndpoints returns a new Endpoints
func newEndpoints() *Endpoints {
	return &Endpoints{
		Backends: map[string]service.PortConfiguration{},
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

	for ip1, ports1 := range e.Backends {
		ports2, ok := o.Backends[ip1]
		if !ok {
			return false
		}

		if len(ports1) != len(ports2) {
			return false
		}

		for portName1, port1 := range ports1 {
			port2, ok := ports2[portName1]

			if !ok || !port1.Equals(port2) {
				return false
			}
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
func ParseEndpointsID(svc *v1.Endpoints) ServiceID {
	return ServiceID{
		Name:      svc.ObjectMeta.Name,
		Namespace: svc.ObjectMeta.Namespace,
	}
}

// ParseEndpoints parses a Kubernetes Endpoints resource
func ParseEndpoints(ep *v1.Endpoints) (ServiceID, *Endpoints) {
	endpoints := newEndpoints()

	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			backend, ok := endpoints.Backends[addr.IP]
			if !ok {
				backend = service.PortConfiguration{}
				endpoints.Backends[addr.IP] = backend
			}

			for _, port := range sub.Ports {
				lbPort := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
				backend[port.Name] = lbPort
			}
		}
	}

	return ParseEndpointsID(ep), endpoints
}
