// Copyright 2018-2021 Authors of Cilium
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
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discovery_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

// Endpoints is an abstraction for the Kubernetes endpoints object. Endpoints
// consists of a set of backend IPs in combination with a set of ports and
// protocols. The name of the backend ports must match the names of the
// frontend ports of the corresponding service.
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type Endpoints struct {
	// Backends is a map containing all backend IPs and ports. The key to
	// the map is the backend IP in string form. The value defines the list
	// of ports for that backend IP, plus an additional optional node name.
	Backends map[string]*Backend
}

// DeepEqual returns true if both endpoints are deep equal.
func (e *Endpoints) DeepEqual(o *Endpoints) bool {
	switch {
	case (e == nil) != (o == nil):
		return false
	case (e == nil) && (o == nil):
		return true
	}
	return e.deepEqual(o)
}

// Backend contains all ports and the node name of a given backend
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
type Backend struct {
	Ports    serviceStore.PortConfiguration
	NodeName string
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
func ParseEndpointsID(svc *slim_corev1.Endpoints) ServiceID {
	return ServiceID{
		Name:      svc.ObjectMeta.Name,
		Namespace: svc.ObjectMeta.Namespace,
	}
}

// ParseEndpoints parses a Kubernetes Endpoints resource
func ParseEndpoints(ep *slim_corev1.Endpoints) (ServiceID, *Endpoints) {
	endpoints := newEndpoints()

	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			backend, ok := endpoints.Backends[addr.IP]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
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

type endpointSlice interface {
	GetNamespace() string
	GetName() string
	GetLabels() map[string]string
}

// ParseEndpointSliceID parses a Kubernetes endpoints slice and returns a
// EndpointSliceID
func ParseEndpointSliceID(es endpointSlice) EndpointSliceID {
	return EndpointSliceID{
		ServiceID: ServiceID{
			Name:      es.GetLabels()[slim_discovery_v1.LabelServiceName],
			Namespace: es.GetNamespace(),
		},
		EndpointSliceName: es.GetName(),
	}
}

// ParseEndpointSliceV1Beta1 parses a Kubernetes EndpointsSlice v1beta1 resource
func ParseEndpointSliceV1Beta1(ep *slim_discovery_v1beta1.EndpointSlice) (EndpointSliceID, *Endpoints) {
	endpoints := newEndpoints()

	for _, sub := range ep.Endpoints {
		// ready indicates that this endpoint is prepared to receive traffic,
		// according to whatever system is managing the endpoint. A nil value
		// indicates an unknown state. In most cases consumers should interpret this
		// unknown state as ready.
		// More info: vendor/k8s.io/api/discovery/v1beta1/types.go:114
		if sub.Conditions.Ready != nil && !*sub.Conditions.Ready {
			continue
		}
		for _, addr := range sub.Addresses {
			backend, ok := endpoints.Backends[addr]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
				endpoints.Backends[addr] = backend
				if nodeName, ok := sub.Topology["kubernetes.io/hostname"]; ok {
					backend.NodeName = nodeName
				}
			}

			for _, port := range ep.Ports {
				name, lbPort := parseEndpointPortV1Beta1(port)
				if lbPort != nil {
					backend.Ports[name] = lbPort
				}
			}
		}
	}

	return ParseEndpointSliceID(ep), endpoints
}

// parseEndpointPortV1Beta1 returns the port name and the port parsed as a
// L4Addr from the given port.
func parseEndpointPortV1Beta1(port slim_discovery_v1beta1.EndpointPort) (string, *loadbalancer.L4Addr) {
	proto := loadbalancer.TCP
	if port.Protocol != nil {
		switch *port.Protocol {
		case slim_corev1.ProtocolTCP:
			proto = loadbalancer.TCP
		case slim_corev1.ProtocolUDP:
			proto = loadbalancer.UDP
		default:
			return "", nil
		}
	}
	if port.Port == nil {
		return "", nil
	}
	var name string
	if port.Name != nil {
		name = *port.Name
	}
	lbPort := loadbalancer.NewL4Addr(proto, uint16(*port.Port))
	return name, lbPort
}

// ParseEndpointSliceV1 parses a Kubernetes Endpoints resource
func ParseEndpointSliceV1(ep *slim_discovery_v1.EndpointSlice) (EndpointSliceID, *Endpoints) {
	endpoints := newEndpoints()

	for _, sub := range ep.Endpoints {
		// ready indicates that this endpoint is prepared to receive traffic,
		// according to whatever system is managing the endpoint. A nil value
		// indicates an unknown state. In most cases consumers should interpret this
		// unknown state as ready.
		// More info: vendor/k8s.io/api/discovery/v1/types.go:117
		if sub.Conditions.Ready != nil && !*sub.Conditions.Ready {
			continue
		}
		for _, addr := range sub.Addresses {
			backend, ok := endpoints.Backends[addr]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
				endpoints.Backends[addr] = backend
				if sub.NodeName != nil {
					backend.NodeName = *sub.NodeName
				} else {
					if nodeName, ok := sub.DeprecatedTopology["kubernetes.io/hostname"]; ok {
						backend.NodeName = nodeName
					}
				}
			}

			for _, port := range ep.Ports {
				name, lbPort := parseEndpointPortV1(port)
				if lbPort != nil {
					backend.Ports[name] = lbPort
				}
			}
		}
	}

	return ParseEndpointSliceID(ep), endpoints
}

// parseEndpointPortV1 returns the port name and the port parsed as a L4Addr from
// the given port.
func parseEndpointPortV1(port slim_discovery_v1.EndpointPort) (string, *loadbalancer.L4Addr) {
	proto := loadbalancer.TCP
	if port.Protocol != nil {
		switch *port.Protocol {
		case slim_corev1.ProtocolTCP:
			proto = loadbalancer.TCP
		case slim_corev1.ProtocolUDP:
			proto = loadbalancer.UDP
		default:
			return "", nil
		}
	}
	if port.Port == nil {
		return "", nil
	}
	var name string
	if port.Name != nil {
		name = *port.Name
	}
	lbPort := loadbalancer.NewL4Addr(proto, uint16(*port.Port))
	return name, lbPort
}

// EndpointSlices is the collection of all endpoint slices of a service.
// The map key is the name of the endpoint slice or the name of the legacy
// v1.Endpoint. The endpoints stored here are not namespaced since this
// structure is only used as a value of another map that is already namespaced.
// (see ServiceCache.endpoints).
//
// +deepequal-gen=true
type EndpointSlices struct {
	epSlices map[string]*Endpoints
}

// newEndpointsSlices returns a new EndpointSlices
func newEndpointsSlices() *EndpointSlices {
	return &EndpointSlices{
		epSlices: map[string]*Endpoints{},
	}
}

// GetEndpoints returns a read only a single *Endpoints structure with all
// Endpoints' backends joined.
func (es *EndpointSlices) GetEndpoints() *Endpoints {
	if es == nil || len(es.epSlices) == 0 {
		return nil
	}
	allEps := newEndpoints()
	for _, eps := range es.epSlices {
		for backend, ep := range eps.Backends {
			allEps.Backends[backend] = ep
		}
	}
	return allEps
}

// Upsert maps the 'esname' to 'e'.
// - 'esName': Name of the Endpoint Slice
// - 'e': Endpoints to store in the map
func (es *EndpointSlices) Upsert(esName string, e *Endpoints) {
	if es == nil {
		panic("BUG: EndpointSlices is nil")
	}
	es.epSlices[esName] = e
}

// Delete deletes the endpoint slice in the internal map. Returns true if there
// are not any more endpoints available in the map.
func (es *EndpointSlices) Delete(esName string) bool {
	if es == nil || len(es.epSlices) == 0 {
		return true
	}
	delete(es.epSlices, esName)
	return len(es.epSlices) == 0
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

// SupportsEndpointSlice returns true if cilium-operator or cilium-agent should
// watch and process endpoint slices.
func SupportsEndpointSlice() bool {
	return version.Capabilities().EndpointSlice && option.Config.K8sEnableK8sEndpointSlice
}

// SupportsEndpointSliceV1 returns true if cilium-operator or cilium-agent should
// watch and process endpoint slices V1.
func SupportsEndpointSliceV1() bool {
	return SupportsEndpointSlice() && version.Capabilities().EndpointSliceV1
}

// HasEndpointSlice returns true if the hasEndpointSlices is closed before the
// controller has been synchronized with k8s.
func HasEndpointSlice(hasEndpointSlices chan struct{}, controller cache.Controller) bool {
	endpointSliceSynced := make(chan struct{})
	go func() {
		cache.WaitForCacheSync(wait.NeverStop, controller.HasSynced)
		close(endpointSliceSynced)
	}()

	// Check if K8s has a single endpointslice endpoint. By default, k8s has
	// always the kubernetes-apiserver endpoint. If the endpointSlice are synced
	// but we haven't received any endpoint slice then it means k8s is not
	// running with k8s endpoint slice enabled.
	select {
	case <-endpointSliceSynced:
		select {
		// In case both select cases are ready to be selected we will recheck if
		// hasEndpointSlices was closed.
		case <-hasEndpointSlices:
			return true
		default:
		}
	case <-hasEndpointSlices:
		return true
	}
	return false
}
