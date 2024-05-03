// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discovery_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
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
// The Endpoints object is parsed from either an EndpointSlice (preferred) or Endpoint
// Kubernetes objects depending on the Kubernetes version.
//
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type Endpoints struct {
	types.UnserializableObject
	slim_metav1.ObjectMeta

	EndpointSliceID

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
	Hostname      string
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

// Prefixes returns the endpoint's backends as a slice of netip.Prefix.
func (e *Endpoints) Prefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(e.Backends))
	for addrCluster := range e.Backends {
		addr := addrCluster.Addr()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes
}

// ParseEndpointsID parses a Kubernetes endpoints and returns the EndpointSliceID
func ParseEndpointsID(ep *slim_corev1.Endpoints) EndpointSliceID {
	return EndpointSliceID{
		ServiceID: ServiceID{
			Name:      ep.ObjectMeta.Name,
			Namespace: ep.ObjectMeta.Namespace,
		},
		EndpointSliceName: ep.ObjectMeta.Name,
	}
}

// ParseEndpoints parses a Kubernetes Endpoints resource
func ParseEndpoints(ep *slim_corev1.Endpoints) *Endpoints {
	endpoints := newEndpoints()
	endpoints.ObjectMeta = ep.ObjectMeta

	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			addrCluster, err := cmtypes.ParseAddrCluster(addr.IP)
			if err != nil {
				continue
			}

			backend, ok := endpoints.Backends[addrCluster]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
				endpoints.Backends[addrCluster] = backend
			}

			if addr.NodeName != nil {
				backend.NodeName = *addr.NodeName
			}
			backend.Hostname = addr.Hostname

			for _, port := range sub.Ports {
				lbPort := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
				backend.Ports[port.Name] = lbPort
			}
		}
	}

	endpoints.EndpointSliceID = ParseEndpointsID(ep)
	return endpoints
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
func ParseEndpointSliceV1Beta1(ep *slim_discovery_v1beta1.EndpointSlice) *Endpoints {
	endpoints := newEndpoints()
	endpoints.ObjectMeta = ep.ObjectMeta
	endpoints.EndpointSliceID = ParseEndpointSliceID(ep)

	// Validate AddressType before parsing. Currently, we only support IPv4 and IPv6.
	if ep.AddressType != slim_discovery_v1beta1.AddressTypeIPv4 &&
		ep.AddressType != slim_discovery_v1beta1.AddressTypeIPv6 {
		return endpoints
	}

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
			addrCluster, err := cmtypes.ParseAddrCluster(addr)
			if err != nil {
				continue
			}

			backend, ok := endpoints.Backends[addrCluster]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
				endpoints.Backends[addrCluster] = backend
				if nodeName, ok := sub.Topology["kubernetes.io/hostname"]; ok {
					backend.NodeName = nodeName
				}
				if sub.Hostname != nil {
					backend.Hostname = *sub.Hostname
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
	return endpoints
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
		case slim_corev1.ProtocolSCTP:
			proto = loadbalancer.SCTP
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
func ParseEndpointSliceV1(ep *slim_discovery_v1.EndpointSlice) *Endpoints {
	endpoints := newEndpoints()
	endpoints.ObjectMeta = ep.ObjectMeta
	endpoints.EndpointSliceID = ParseEndpointSliceID(ep)

	// Validate AddressType before parsing. Currently, we only support IPv4 and IPv6.
	if ep.AddressType != slim_discovery_v1.AddressTypeIPv4 &&
		ep.AddressType != slim_discovery_v1.AddressTypeIPv6 {
		return endpoints
	}

	log.Debugf("Processing %d endpoints for EndpointSlice %s", len(ep.Endpoints), ep.Name)
	for _, sub := range ep.Endpoints {
		// ready indicates that this endpoint is prepared to receive traffic,
		// according to whatever system is managing the endpoint. A nil value
		// indicates an unknown state. In most cases consumers should interpret this
		// unknown state as ready.
		// More info: vendor/k8s.io/api/discovery/v1/types.go
		isReady := sub.Conditions.Ready == nil || *sub.Conditions.Ready
		// serving is identical to ready except that it is set regardless of the
		// terminating state of endpoints. This condition should be set to true for
		// a ready endpoint that is terminating. If nil, consumers should defer to
		// the ready condition.
		// More info: vendor/k8s.io/api/discovery/v1/types.go
		isServing := (sub.Conditions.Serving == nil && isReady) || (sub.Conditions.Serving != nil && *sub.Conditions.Serving)
		// Terminating indicates that the endpoint is getting terminated. A
		// nil values indicates an unknown state. Ready is never true when
		// an endpoint is terminating. Propagate the terminating endpoint
		// state so that we can gracefully remove those endpoints.
		// More info: vendor/k8s.io/api/discovery/v1/types.go
		isTerminating := sub.Conditions.Terminating != nil && *sub.Conditions.Terminating

		// if is not Ready and EnableK8sTerminatingEndpoint is set
		// allow endpoints that are Serving and Terminating
		if !isReady {
			if !option.Config.EnableK8sTerminatingEndpoint {
				log.Debugf("discarding Endpoint on EndpointSlice %s: not Ready and EnableK8sTerminatingEndpoint %v", ep.Name, option.Config.EnableK8sTerminatingEndpoint)
				continue
			}
			// filter not Serving endpoints since those can not receive traffic
			if !isServing {
				log.Debugf("discarding Endpoint on EndpointSlice %s: not Serving and EnableK8sTerminatingEndpoint %v", ep.Name, option.Config.EnableK8sTerminatingEndpoint)
				continue
			}
		}

		for _, addr := range sub.Addresses {
			addrCluster, err := cmtypes.ParseAddrCluster(addr)
			if err != nil {
				log.WithError(err).Infof("Unable to parse address %s for EndpointSlices %s", addr, ep.Name)
				continue
			}

			backend, ok := endpoints.Backends[addrCluster]
			if !ok {
				backend = &Backend{Ports: serviceStore.PortConfiguration{}}
				endpoints.Backends[addrCluster] = backend
				if sub.NodeName != nil {
					backend.NodeName = *sub.NodeName
				} else {
					if nodeName, ok := sub.DeprecatedTopology["kubernetes.io/hostname"]; ok {
						backend.NodeName = nodeName
					}
				}
				if sub.Hostname != nil {
					backend.Hostname = *sub.Hostname
				}
				// If is not ready check if is serving and terminating
				if !isReady && option.Config.EnableK8sTerminatingEndpoint &&
					isServing && isTerminating {
					log.Debugf("Endpoint address %s on EndpointSlice %s is Terminating", addr, ep.Name)
					backend.Terminating = true
					metrics.TerminatingEndpointsEvents.Inc()
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

	log.Debugf("EndpointSlice %s has %d backends", ep.Name, len(endpoints.Backends))
	return endpoints
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
		case slim_corev1.ProtocolSCTP:
			proto = loadbalancer.SCTP
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
			// EndpointSlices may have duplicate addresses on different slices.
			// kubectl get endpointslices -n endpointslicemirroring-4896
			// NAME                             ADDRESSTYPE   PORTS   ENDPOINTS     AGE
			// example-custom-endpoints-f6z84   IPv4          9090    10.244.1.49   28s
			// example-custom-endpoints-g6r6v   IPv4          8090    10.244.1.49   28s
			b, ok := allEps.Backends[backend]
			if !ok {
				allEps.Backends[backend] = ep.DeepCopy()
			} else {
				clone := b.DeepCopy()
				for k, v := range ep.Ports {
					clone.Ports[k] = v
				}
				allEps.Backends[backend] = clone
			}
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
