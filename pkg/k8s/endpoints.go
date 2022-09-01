// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ip"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discovery_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
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
	// Backends map[cmtypes.AddrCluster]*Backend
	Backends map[cmtypes.AddrCluster]*Backend
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

func (in *Endpoints) DeepCopyInto(out *Endpoints) {
	*out = *in
	if in.Backends != nil {
		in, out := &in.Backends, &out.Backends
		*out = make(map[cmtypes.AddrCluster]*Backend, len(*in))
		for key, val := range *in {
			var outVal *Backend
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(Backend)
				(*in).DeepCopyInto(*out)
			}
			(*out)[key] = outVal
		}
	}
	return
}

func (in *Endpoints) DeepCopy() *Endpoints {
	if in == nil {
		return nil
	}
	out := new(Endpoints)
	in.DeepCopyInto(out)
	return out
}

// Backend contains all ports, terminating state, and the node name of a given backend
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
type Backend struct {
	Ports         serviceStore.PortConfiguration
	NodeName      string
	Terminating   bool
	HintsForZones []string
	Preferred     bool
}

// String returns the string representation of an endpoints resource, with
// backends and ports sorted.
func (e *Endpoints) String() string {
	if e == nil {
		return ""
	}

	backends := []string{}
	for addrCluster, be := range e.Backends {
		for _, port := range be.Ports {
			backends = append(backends, fmt.Sprintf("%s/%s", net.JoinHostPort(addrCluster.Addr().String(), strconv.Itoa(int(port.Port))), port.Protocol))
		}
	}

	sort.Strings(backends)

	return strings.Join(backends, ",")
}

// newEndpoints returns a new Endpoints
func newEndpoints() *Endpoints {
	return &Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{},
	}
}

// CIDRPrefixes returns the endpoint's backends as a slice of IPNets.
func (e *Endpoints) CIDRPrefixes() ([]*net.IPNet, error) {
	prefixes := make([]string, len(e.Backends))
	index := 0
	for addrCluster := range e.Backends {
		prefixes[index] = addrCluster.Addr().String()
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
			backend, ok := endpoints.Backends[cmtypes.MustParseAddrCluster(addr.IP)]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
				endpoints.Backends[cmtypes.MustParseAddrCluster(addr.IP)] = backend
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
// It reads ready and terminating state of endpoints in the EndpointSlice to
// return an EndpointSlice ID and a filtered list of Endpoints for service load-balancing.
func ParseEndpointSliceV1Beta1(ep *slim_discovery_v1beta1.EndpointSlice) (EndpointSliceID, *Endpoints) {
	endpoints := newEndpoints()

	for _, sub := range ep.Endpoints {
		skipEndpoint := false
		// ready indicates that this endpoint is prepared to receive traffic,
		// according to whatever system is managing the endpoint. A nil value
		// indicates an unknown state. In most cases consumers should interpret this
		// unknown state as ready.
		// More info: vendor/k8s.io/api/discovery/v1beta1/types.go
		if sub.Conditions.Ready != nil && !*sub.Conditions.Ready {
			skipEndpoint = true
			if option.Config.EnableK8sTerminatingEndpoint {
				// Terminating indicates that the endpoint is getting terminated. A
				// nil values indicates an unknown state. Ready is never true when
				// an endpoint is terminating. Propagate the terminating endpoint
				// state so that we can gracefully remove those endpoints.
				// More details : vendor/k8s.io/api/discovery/v1/types.go
				if sub.Conditions.Terminating != nil && *sub.Conditions.Terminating {
					skipEndpoint = false
				}
			}
		}
		if skipEndpoint {
			continue
		}
		for _, addr := range sub.Addresses {
			backend, ok := endpoints.Backends[cmtypes.MustParseAddrCluster(addr)]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
				endpoints.Backends[cmtypes.MustParseAddrCluster(addr)] = backend
				if nodeName, ok := sub.Topology["kubernetes.io/hostname"]; ok {
					backend.NodeName = nodeName
				}
				if option.Config.EnableK8sTerminatingEndpoint {
					if sub.Conditions.Terminating != nil && *sub.Conditions.Terminating {
						backend.Terminating = true
						metrics.TerminatingEndpointsEvents.Inc()
					}
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

// ParseEndpointSliceV1 parses a Kubernetes EndpointSlice resource.
// It reads ready and terminating state of endpoints in the EndpointSlice to
// return an EndpointSlice ID and a filtered list of Endpoints for service load-balancing.
func ParseEndpointSliceV1(ep *slim_discovery_v1.EndpointSlice) (EndpointSliceID, *Endpoints) {
	endpoints := newEndpoints()

	for _, sub := range ep.Endpoints {
		skipEndpoint := false
		// ready indicates that this endpoint is prepared to receive traffic,
		// according to whatever system is managing the endpoint. A nil value
		// indicates an unknown state. In most cases consumers should interpret this
		// unknown state as ready.
		// More info: vendor/k8s.io/api/discovery/v1/types.go
		if sub.Conditions.Ready != nil && !*sub.Conditions.Ready {
			skipEndpoint = true
			if option.Config.EnableK8sTerminatingEndpoint {
				// Terminating indicates that the endpoint is getting terminated. A
				// nil values indicates an unknown state. Ready is never true when
				// an endpoint is terminating. Propagate the terminating endpoint
				// state so that we can gracefully remove those endpoints.
				// More details : vendor/k8s.io/api/discovery/v1/types.go
				if sub.Conditions.Terminating != nil && *sub.Conditions.Terminating {
					skipEndpoint = false
				}
			}
		}
		if skipEndpoint {
			continue
		}
		for _, addr := range sub.Addresses {
			backend, ok := endpoints.Backends[cmtypes.MustParseAddrCluster(addr)]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
				endpoints.Backends[cmtypes.MustParseAddrCluster(addr)] = backend
				if sub.NodeName != nil {
					backend.NodeName = *sub.NodeName
				} else {
					if nodeName, ok := sub.DeprecatedTopology["kubernetes.io/hostname"]; ok {
						backend.NodeName = nodeName
					}
				}
				if option.Config.EnableK8sTerminatingEndpoint {
					if sub.Conditions.Terminating != nil && *sub.Conditions.Terminating {
						backend.Terminating = true
						metrics.TerminatingEndpointsEvents.Inc()
					}
				}
			}

			for _, port := range ep.Ports {
				name, lbPort := parseEndpointPortV1(port)
				if lbPort != nil {
					backend.Ports[name] = lbPort
				}
			}
			if sub.Hints != nil && (*sub.Hints).ForZones != nil {
				hints := (*sub.Hints).ForZones
				backend.HintsForZones = make([]string, len(hints))
				for i, hint := range hints {
					backend.HintsForZones[i] = hint.Name
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
