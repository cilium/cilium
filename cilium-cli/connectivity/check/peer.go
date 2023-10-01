// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"net"
	"net/url"
	"strconv"

	"github.com/cilium/cilium/api/v1/flow"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/utils/features"
)

// TestPeer is the abstraction used for all peer types (pods, services, IPs,
// DNS names) used for connectivity testing
type TestPeer interface {
	// Name must return the absolute name of the peer.
	Name() string

	// Scheme must return the scheme to be used in a connection string
	// to connect to this peer, e.g. 'http' or 'https'. Can be an empty string.
	Scheme() string

	// Path must return the path in the URL used, if any. Can be an empty
	// string. Must include the leading '/' when not empty.
	Path() string

	// Address must return the network address of the peer. This can be a
	// DNS name or an IP address.
	Address(features.IPFamily) string

	// Port must return the destination port number used by the test traffic to the peer.
	Port() uint32

	// HasLabel checks if given label with the given name and value exists.
	HasLabel(name, value string) bool

	// Labels returns copy of peer labels
	Labels() map[string]string

	FlowFilters() []*flow.FlowFilter
}

// Pod is a Kubernetes Pod acting as a peer in a connectivity test.
type Pod struct {
	// Kubernetes client of the cluster this pod is running in.
	K8sClient *k8s.Client

	// Pod is the Kubernetes Pod resource.
	Pod *corev1.Pod

	// Scheme to be used to connect to the service running in the Pod.
	// (e.g. 'http')
	scheme string

	// Path to be used to connect to the service running in the Pod.
	// (e.g. '/')
	path string

	// Port the Pods is listening on for connectivity tests.
	port uint32

	// The pod is running on a node which doesn't run Cilium
	Outside bool
}

func (p Pod) String() string {
	return p.Name()
}

// Name returns the absolute name of the Pod.
func (p Pod) Name() string {
	return p.Pod.Namespace + "/" + p.Pod.Name
}

// NameWithoutNamespace returns only the name of the Pod.
func (p Pod) NameWithoutNamespace() string {
	return p.Pod.Name
}

// NodeName returns the node name a pod belongs to.
func (p Pod) NodeName() string {
	return p.Pod.Spec.NodeName
}

// Namespace returns the namespace the pod belongs to.
func (p Pod) Namespace() string {
	return p.Pod.Namespace
}

func (p Pod) Scheme() string {
	return p.scheme
}

func (p Pod) Path() string {
	return p.path
}

// Address returns the network address of the Pod.
func (p Pod) Address(family features.IPFamily) string {
	for _, addr := range p.Pod.Status.PodIPs {
		ip := net.ParseIP(addr.IP)
		if (family == features.IPFamilyV4 || family == features.IPFamilyAny) && ip.To4() != nil {
			return addr.IP
		}
		if (family == features.IPFamilyV6 || family == features.IPFamilyAny) && ip.To4() == nil && ip.To16() != nil {
			return addr.IP
		}
	}
	return ""
}

// HasLabel checks if given label exists and value matches.
func (p Pod) HasLabel(name, value string) bool {
	v, ok := p.Pod.Labels[name]
	return ok && v == value
}

// Port returns the port the Pod is listening on.
func (p Pod) Port() uint32 {
	return p.port
}

func (p Pod) Labels() map[string]string {
	newMap := make(map[string]string, len(p.Pod.Labels))
	for k, v := range p.Pod.Labels {
		newMap[k] = v
	}
	return newMap
}

func (p Pod) FlowFilters() []*flow.FlowFilter {
	// When pod is a host netns pod running on a node w/o Cilium, we need to use
	// that pod IP addrs (=host IP) for flow filtering, as Hubble is not aware
	// of that pod name because it doesn't belong to a Cilium cluster.
	if p.Outside {
		podIPs := make([]string, 0, len(p.Pod.Status.PodIPs))
		for _, ip := range p.Pod.Status.PodIPs {
			podIPs = append(podIPs, ip.IP)
		}
		return []*flow.FlowFilter{
			{DestinationIp: podIPs},
			{SourceIp: podIPs},
		}
	}

	return []*flow.FlowFilter{
		{SourcePod: []string{p.Name()}},
		{DestinationPod: []string{p.Name()}},
	}

}

// Service is a service acting as a peer in a connectivity test.
// It implements interface TestPeer.
type Service struct {
	// Service  is the Kubernetes service resource
	Service *corev1.Service
}

// Name returns the absolute name of the service.
func (s Service) Name() string {
	return s.Service.Namespace + "/" + s.Service.Name
}

// NameWithoutNamespace returns the name of the service without the namespace.
func (s Service) NameWithoutNamespace() string {
	return s.Service.Name
}

// Scheme returns the string 'http'.
func (s Service) Scheme() string {
	// We only have http services for now.
	return "http"
}

// Path returns the string '/'.
func (s Service) Path() string {
	// No support for paths yet.
	return ""
}

// Address returns the network address of the Service.
func (s Service) Address(family features.IPFamily) string {
	// If the cluster IP is empty (headless service case) or the IP family is set to any, return the service name
	if s.Service.Spec.ClusterIP == "" || family == features.IPFamilyAny {
		return s.Service.Name
	}

	getClusterIPForIPFamily := func(family v1.IPFamily) string {
		for i, f := range s.Service.Spec.IPFamilies {
			if f == family {
				return s.Service.Spec.ClusterIPs[i]
			}
		}

		return ""
	}

	switch family {
	case features.IPFamilyV4:
		return getClusterIPForIPFamily(v1.IPv4Protocol)
	case features.IPFamilyV6:
		return getClusterIPForIPFamily(v1.IPv6Protocol)
	}

	return ""
}

// Port returns the first port of the Service.
func (s Service) Port() uint32 {
	return uint32(s.Service.Spec.Ports[0].Port)
}

// HasLabel checks if given label exists and value matches.
func (s Service) HasLabel(name, value string) bool {
	v, ok := s.Service.Labels[name]
	return ok && v == value
}

// Labels returns the copy of service labels
func (s Service) Labels() map[string]string {
	newMap := make(map[string]string, len(s.Service.Labels))
	for k, v := range s.Service.Labels {
		newMap[k] = v
	}
	return newMap
}

func (s Service) FlowFilters() []*flow.FlowFilter {
	return nil
}

func (s Service) ToNodeportService(node *v1.Node) NodeportService {
	return NodeportService{
		Service: s,
		Node:    node,
	}
}

// NodeportService wraps a Service and exposes it through its nodeport, acting as a peer in a connectivity test.
// It implements interface TestPeer.
type NodeportService struct {
	Service Service
	Node    *v1.Node
}

// Name returns name of the wrapped service.
func (s NodeportService) Name() string {
	return s.Service.Name()
}

// Scheme returns the scheme of the wrapped service.
func (s NodeportService) Scheme() string {
	return s.Service.Scheme()
}

// Path returns the path of the wrapped service.
func (s NodeportService) Path() string {
	return s.Service.Path()
}

// Address returns the node IP of the wrapped Service.
func (s NodeportService) Address(family features.IPFamily) string {
	if family == features.IPFamilyAny {
		return s.Node.Status.Addresses[0].Address
	}

	for _, address := range s.Node.Status.Addresses {
		if address.Type == v1.NodeInternalIP {
			parsedAddress := net.ParseIP(address.Address)

			switch family {
			case features.IPFamilyV4:
				if parsedAddress.To4() != nil {
					return address.Address
				}
			case features.IPFamilyV6:
				if parsedAddress.To16() != nil {
					return address.Address
				}
			}
		}
	}

	return ""
}

// Port returns the first nodeport of the wrapped Service.
func (s NodeportService) Port() uint32 {
	return uint32(s.Service.Service.Spec.Ports[0].NodePort)
}

// HasLabel checks if given label exists and value matches.
func (s NodeportService) HasLabel(name, value string) bool {
	return s.Service.HasLabel(name, value)
}

// Labels returns the copy of service labels
func (s NodeportService) Labels() map[string]string {
	return s.Service.Labels()
}

func (s NodeportService) FlowFilters() []*flow.FlowFilter {
	return s.Service.FlowFilters()
}

// ExternalWorkload is an external workload acting as a peer in a
// connectivity test. It implements interface TestPeer.
type ExternalWorkload struct {
	// workload is the Kubernetes Cilium external workload resource.
	workload *ciliumv2.CiliumExternalWorkload
}

// Name returns the name of the ExternalWorkload.
func (e ExternalWorkload) Name() string {
	return e.workload.Namespace + "/" + e.workload.Name
}

// Scheme returns an empty string.
func (e ExternalWorkload) Scheme() string {
	return ""
}

// Path returns an empty string.
func (e ExternalWorkload) Path() string {
	return ""
}

// Address returns the network address of the ExternalWorkload.
func (e ExternalWorkload) Address(features.IPFamily) string {
	return e.workload.Status.IP
}

// Port returns 0.
func (e ExternalWorkload) Port() uint32 {
	return 0
}

// HasLabel checks if given label exists and value matches.
func (e ExternalWorkload) HasLabel(name, value string) bool {
	v, ok := e.workload.Labels[name]
	return ok && v == value
}

// Labels returns the copy of labels
func (e ExternalWorkload) Labels() map[string]string {
	newMap := make(map[string]string, len(e.workload.Labels))
	for k, v := range e.workload.Labels {
		newMap[k] = v
	}
	return newMap
}

func (e ExternalWorkload) FlowFilters() []*flow.FlowFilter {
	return nil
}

// ICMPEndpoint returns a new ICMP endpoint.
func ICMPEndpoint(name, host string) TestPeer {
	return icmpEndpoint{
		name: name,
		host: host,
	}
}

// icmpEndpoint is an ICMP endpoint acting as a peer in a connectivity test.
// It implements interface TestPeer.
type icmpEndpoint struct {
	// Name of the endpoint.
	name string

	// Address of the endpoint.
	host string
}

// Name is the absolute name of the network endpoint.
func (ie icmpEndpoint) Name() string {
	if ie.name != "" {
		return ie.name
	}

	return ie.host
}

func (ie icmpEndpoint) Scheme() string {
	return ""
}

func (ie icmpEndpoint) Path() string {
	return ""
}
func (ie icmpEndpoint) Address(features.IPFamily) string {
	return ie.host
}

func (ie icmpEndpoint) Port() uint32 {
	return 0
}

// HasLabel checks if given label exists and value matches.
func (ie icmpEndpoint) HasLabel(_, _ string) bool {
	return false
}

// Labels returns the copy of labels
func (ie icmpEndpoint) Labels() map[string]string {
	return make(map[string]string)
}

func (ie icmpEndpoint) FlowFilters() []*flow.FlowFilter {
	return nil
}

// HTTPEndpoint returns a new endpoint with the given name and raw URL.
// Panics if rawurl cannot be parsed.
func HTTPEndpoint(name, rawurl string) TestPeer {
	return HTTPEndpointWithLabels(name, rawurl, nil)
}

func HTTPEndpointWithLabels(name, rawurl string, labels map[string]string) TestPeer {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}

	return httpEndpoint{
		name:   name,
		url:    u,
		labels: &labels,
	}
}

// httpEndpoint is an HTTP endpoint acting as a peer in a connectivity test.
// It implements interface TestPeer.
type httpEndpoint struct {
	// Name of the endpoint.
	name string

	// URL of the endpoint.
	url *url.URL

	// Labels associated with the endpoint. These are used to match whether a policy drop should
	// have happened or not based on HTTP headers.
	labels *map[string]string
}

func (he httpEndpoint) Name() string {
	if he.name != "" {
		return he.name
	}
	return he.url.Hostname()
}

func (he httpEndpoint) Scheme() string {
	return he.url.Scheme
}

func (he httpEndpoint) Path() string {
	return he.url.Path
}

func (he httpEndpoint) Address(features.IPFamily) string {
	return he.url.Hostname()
}

func (he httpEndpoint) Port() uint32 {
	p := he.url.Port()
	if p != "" {
		u, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return 0
		}
		return uint32(u)
	}

	if he.url.Scheme == "https" {
		return 443
	}

	// Use port 80 when no scheme and port specified.
	return 80
}

func (he httpEndpoint) HasLabel(name, value string) bool {
	if he.labels == nil {
		return false
	}
	return (*he.labels)[name] == value
}

func (he httpEndpoint) Labels() map[string]string {
	newMap := make(map[string]string, len(*he.labels))
	for k, v := range *he.labels {
		newMap[k] = v
	}
	return newMap
}

func (he httpEndpoint) FlowFilters() []*flow.FlowFilter {
	return nil
}
