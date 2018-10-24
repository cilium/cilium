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
	"strings"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/loadbalancer"

	"k8s.io/api/core/v1"
)

// Endpoints is an abstraction for the kubernetes endpoints object. Each
// service is composed by a set of backend IPs (BEIPs) and a map of Ports
// (Ports). Each k8s endpoint present in BEIPs share the same list of Ports
// open.
type Endpoints struct {
	// TODO: Replace bool for time.Time so we know last time the service endpoint was seen?
	BackendIPs map[string]bool
	Ports      map[loadbalancer.FEPortName]*loadbalancer.L4Addr
}

// String returns the string representation of an endpoints resource
func (e *Endpoints) String() string {
	if e == nil {
		return "nil"
	}

	backends := make([]string, len(e.BackendIPs))
	i := 0
	for ip := range e.BackendIPs {
		backends[i] = ip
		i++
	}

	ports := make([]string, len(e.Ports))
	i = 0
	for p := range e.Ports {
		ports[i] = string(p)
		i++
	}

	return fmt.Sprintf("backends:%v/ports:%v", strings.Join(backends, ","), strings.Join(ports, ","))
}

// NewEndpoints returns a new Endpoints
func NewEndpoints() *Endpoints {
	return &Endpoints{
		BackendIPs: map[string]bool{},
		Ports:      map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
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

	if !comparator.MapBoolEquals(e.BackendIPs, o.BackendIPs) {
		return false
	}

	if len(e.Ports) != len(o.Ports) {
		return false
	}

	for k1, v1 := range e.Ports {
		v2, ok := o.Ports[k1]
		if !ok || !v1.Equals(v2) {
			return false
		}
	}

	return true
}

// CIDRPrefixes returns the endpoint's backends as a slice of IPNets.
func (e *Endpoints) CIDRPrefixes() ([]*net.IPNet, error) {
	prefixes := make([]string, 0, len(e.BackendIPs))
	for backend := range e.BackendIPs {
		prefixes = append(prefixes, backend)
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
	endpoints := NewEndpoints()

	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			endpoints.BackendIPs[addr.IP] = true
		}

		for _, port := range sub.Ports {
			lbPort := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			endpoints.Ports[loadbalancer.FEPortName(port.Name)] = lbPort
		}
	}

	return ParseEndpointsID(ep), endpoints
}
