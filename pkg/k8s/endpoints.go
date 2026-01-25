// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

// EndpointSliceID identifies a Kubernetes EndpointSlice as well as the legacy
// v1.Endpoints.
type EndpointSliceID struct {
	ServiceName       loadbalancer.ServiceName
	EndpointSliceName string
}

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

// BackendCondition is a flag mirroring the endpoint Conditions.
type BackendCondition uint8

const (
	// BackendConditionReady indicates that this endpoint is prepared to receive traffic,
	// according to whatever system is managing the endpoint.
	// More info: vendor/k8s.io/api/discovery/v1/types.go
	// See also https://github.com/kubernetes/kubernetes/issues/108523
	BackendConditionReady = 1 << iota

	// BackendConditionServing indicates that this endpoint can serve new connections.
	// It is meaningful to Cilium when the backend is terminating. If this condition is false
	// then a terminating backend will not be used for new connections even as fallback
	// when no active backends exist.
	// More info: vendor/k8s.io/api/discovery/v1/types.go
	// See also https://github.com/kubernetes/kubernetes/issues/108523 and
	// https://github.com/kubernetes/kubernetes/blob/790393ae92e97262827d4f1fba24e8ae65bbada0/pkg/proxy/topology.go#L76
	BackendConditionServing

	// Terminating indicates that the endpoint is getting terminated.
	// It will not be used for new conditions unless 1) no active backends exist
	// and 2) this backend is serving.
	//
	// If [publishNotReadyAddresses] is set on a service then a backend may be
	// both terminating and ready in which case the terminating state is ignored.
	//
	// More info: vendor/k8s.io/api/discovery/v1/types.go
	// See also https://github.com/kubernetes/kubernetes/issues/108523
	BackendConditionTerminating
)

var backendConditions = [...]string{
	BackendConditionReady:       "ready",
	BackendConditionServing:     "serving",
	BackendConditionTerminating: "terminating",
}

func (bc BackendCondition) String() string {
	var flags []string
	for mask, str := range backendConditions {
		if str != "" && bc&BackendCondition(mask) != 0 {
			flags = append(flags, str)
		}
	}
	return strings.Join(flags, "+")
}

func (bc BackendCondition) IsReady() bool       { return bc&BackendConditionReady != 0 }
func (bc BackendCondition) IsServing() bool     { return bc&BackendConditionServing != 0 }
func (bc BackendCondition) IsTerminating() bool { return bc&BackendConditionTerminating != 0 }

// Backend contains all ports, conditions, and the node name of a given backend
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=false
type Backend struct {
	Ports         map[loadbalancer.L4Addr][]string
	NodeName      string
	Hostname      string
	Conditions    BackendCondition
	HintsForZones []string
	Preferred     bool
	Zone          string
}

func (b *Backend) DeepEqual(other *Backend) bool {
	return maps.EqualFunc(b.Ports, other.Ports, slices.Equal) &&
		b.NodeName == other.NodeName &&
		b.Hostname == other.Hostname &&
		b.Conditions == other.Conditions &&
		slices.Equal(b.HintsForZones, other.HintsForZones) &&
		b.Preferred == other.Preferred &&
		b.Zone == other.Zone
}

func (b *Backend) ToPortConfiguration() serviceStore.PortConfiguration {
	pc := serviceStore.PortConfiguration{}
	for addr, names := range b.Ports {
		for _, name := range names {
			pc[name] = &addr
		}
	}
	return pc
}

// String returns the string representation of an endpoints resource, with
// backends and ports sorted.
func (e *Endpoints) String() string {
	if e == nil {
		return ""
	}

	backends := []string{}
	for addrCluster, be := range e.Backends {
		for port := range be.Ports {
			if be.Zone != "" {
				backends = append(backends, fmt.Sprintf("%s/%s[%s]", net.JoinHostPort(addrCluster.Addr().String(), strconv.Itoa(int(port.Port))), port.Protocol, be.Zone))
			} else {
				backends = append(backends, fmt.Sprintf("%s/%s", net.JoinHostPort(addrCluster.Addr().String(), strconv.Itoa(int(port.Port))), port.Protocol))
			}
		}
	}

	slices.Sort(backends)

	return strings.Join(backends, ",")
}

// newEndpoints returns a new Endpoints
func newEndpoints(initialBackendsSize int) *Endpoints {
	return &Endpoints{
		Backends: make(map[cmtypes.AddrCluster]*Backend, initialBackendsSize),
	}
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
		ServiceName: loadbalancer.NewServiceName(
			es.GetNamespace(),
			es.GetLabels()[slim_discovery_v1.LabelServiceName],
		),
		EndpointSliceName: es.GetNamespace() + "/" + es.GetName(),
	}
}

const logfieldTerminating = "terminating"

func ParseEndpointConditionsV1(conditions slim_discovery_v1.EndpointConditions) (bc BackendCondition) {
	if conditions.Ready == nil || *conditions.Ready {
		bc |= BackendConditionReady
	}
	if conditions.Serving == nil || conditions.Serving != nil && *conditions.Serving {
		bc |= BackendConditionServing
	}
	if conditions.Terminating != nil && *conditions.Terminating {
		bc |= BackendConditionTerminating
	}
	return
}

// ParseEndpointSliceV1 parses a Kubernetes EndpointSlice resource.
// It reads ready and terminating state of endpoints in the EndpointSlice to
// return an EndpointSlice ID and a filtered list of Endpoints for service load-balancing.
func ParseEndpointSliceV1(logger *slog.Logger, ep *slim_discovery_v1.EndpointSlice) *Endpoints {
	// Precalculate the number of backends we'll add to pre-allocate enough room in the backends map.
	backendCount := 0
	for _, sub := range ep.Endpoints {
		backendCount += len(sub.Addresses)
	}
	endpoints := newEndpoints(backendCount)
	endpoints.ObjectMeta = ep.ObjectMeta
	endpoints.EndpointSliceID = ParseEndpointSliceID(ep)

	// Validate AddressType before parsing. Currently, we only support IPv4 and IPv6.
	if ep.AddressType != slim_discovery_v1.AddressTypeIPv4 &&
		ep.AddressType != slim_discovery_v1.AddressTypeIPv6 {
		return endpoints
	}

	logger.Debug("Processing endpoints for EndpointSlice",
		logfields.LenEndpoints, len(ep.Endpoints),
		logfields.Name, ep.Name,
	)

	// Parse the ports shared by all the backends.
	ports := make(map[loadbalancer.L4Addr][]string, len(ep.Ports))
	for _, port := range ep.Ports {
		if name, lbPort, ok := parseEndpointPortV1(port); ok {
			ports[lbPort] = append(ports[lbPort], name)
		}
	}

	for i, sub := range ep.Endpoints {
		// Construct the backend configuration shared by all the addresses in this slice.
		backend := &Backend{
			Conditions: ParseEndpointConditionsV1(sub.Conditions),
			Ports:      ports,
		}

		if sub.NodeName != nil {
			backend.NodeName = *sub.NodeName
		} else {
			if nodeName, ok := sub.DeprecatedTopology[corev1.LabelHostname]; ok {
				backend.NodeName = nodeName
			}
		}

		if sub.Hostname != nil {
			backend.Hostname = *sub.Hostname
		}
		if sub.Zone != nil {
			backend.Zone = *sub.Zone
		} else if zoneName, ok := sub.DeprecatedTopology[corev1.LabelTopologyZone]; ok {
			backend.Zone = zoneName
		}

		if sub.Hints != nil && (*sub.Hints).ForZones != nil {
			hints := (*sub.Hints).ForZones
			backend.HintsForZones = make([]string, len(hints))
			for i, hint := range hints {
				backend.HintsForZones[i] = hint.Name
			}
		}

		// Add reference to the backend configuration for each of the addresses.
		for _, addr := range sub.Addresses {
			addrCluster, err := cmtypes.ParseAddrCluster(addr)
			if err != nil {
				logger.Info(
					"Unable to parse address in EndpointSlice",
					logfields.Error, err,
					logfields.Address, addr,
					logfields.Name, ep.Name,
				)
				continue
			}
			endpoints.Backends[addrCluster] = backend
		}

		if backend.Conditions.IsTerminating() {
			metrics.TerminatingEndpointsEvents.Inc()
		}

		logger.Debug("Processed endpoint",
			logfields.Index, i,
			logfields.Name, ep.Name,
			logfields.Addresses, sub.Addresses,
			logfields.Backend, backend,
			logfieldTerminating, backend.Conditions.IsTerminating(),
		)
	}

	return endpoints
}

// parseEndpointPortV1 returns the port name and the port parsed as a L4Addr from
// the given port.
func parseEndpointPortV1(port slim_discovery_v1.EndpointPort) (name string, addr loadbalancer.L4Addr, ok bool) {
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
			return
		}
	}
	if port.Port == nil {
		return
	}
	if port.Name != nil {
		name = *port.Name
	}
	return name, loadbalancer.NewL4Addr(proto, uint16(*port.Port)), true
}
