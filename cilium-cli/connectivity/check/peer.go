// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package check

import (
	"net/url"
	"strconv"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium-cli/k8s"
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
	Address() string

	// Port must return the destination port number used by the test traffic to the peer.
	Port() uint32

	// HasLabel checks if given label with the given name and value exists.
	HasLabel(name, value string) bool
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
}

func (p Pod) String() string {
	return p.Name()
}

// Name returns the absolute name of the Pod.
func (p Pod) Name() string {
	return p.Pod.Namespace + "/" + p.Pod.Name
}

func (p Pod) Scheme() string {
	return p.scheme
}

func (p Pod) Path() string {
	return p.path
}

// Address returns the network address of the Pod.
func (p Pod) Address() string {
	return p.Pod.Status.PodIP
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
func (s Service) Address() string {
	return s.Service.Name
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
func (e ExternalWorkload) Address() string {
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
func (ie icmpEndpoint) Address() string {
	return ie.host
}

func (ie icmpEndpoint) Port() uint32 {
	return 0
}

// HasLabel checks if given label exists and value matches.
func (ie icmpEndpoint) HasLabel(name, value string) bool {
	return false
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

func (he httpEndpoint) Address() string {
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
