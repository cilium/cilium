// Copyright 2017 Authors of Cilium
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

// Package logfields defines common logging fields which are used across packages
package logfields

const (

	// LogSubsys is the field denoting the subsystem when logging
	LogSubsys = "subsys"

	// Node is a host machine in the cluster, running cilium
	Node = "node"

	// NodeName is a human readable name for the node
	NodeName = "nodeName"

	// EndpointID is the numeric endpoint identifier
	EndpointID = "endpointID"

	// EndpointState is the current endpoint state
	EndpointState = "endpointState"

	// ContainerID is the container identifier
	ContainerID = "containerID"

	// IdentityLabels are the labels relevant for the security identity
	IdentityLabels = "identityLabels"

	// InfoLabels are the labels relevant for the security identity
	InfoLabels = "infoLabels"

	// Labels are any label, they may not be relevant to the security identity.
	Labels = "labels"

	// Identity is the identifier of a security identity
	Identity = "identity"

	// PolicyRevision is the revision of the policy in the repository or of
	// the object in question
	PolicyRevision = "policyRevision"

	// PolicyID is the identifier of a L3, L4 or L7 Policy. Ideally the .NumericIdentity
	PolicyID = "policyID"

	// L3PolicyID is the identifier of a L3 Policy
	L3PolicyID = "policyID.L3"

	// L4PolicyID is the identifier of a L4 Policy
	L4PolicyID = "PolicyID.L4"

	// IPAddr is an IPV4 or IPv6 address
	IPAddr = "ipAddr"

	// V4HealthIP is an address used to contact the cilium-health endpoint
	V4HealthIP = "v4healthIP.IPv4"

	// V6HealthIP is an address used to contact the cilium-health endpoint
	V6HealthIP = "v6healthIP.IPv6"

	// L3n4Addr is a L3 (IP) + L4 (port and protocol) address object.
	L3n4Addr = "l3n4Addr"

	// L3n4AddrID is the allocated ID for a L3n4Addr object
	L3n4AddrID = "l3n4AddrID"

	// Port is a L4 port
	Port = "port"

	// Protocol is the L4 protocol
	Protocol = "protocol"

	// V4Prefix is a IPv4 subnet/CIDR prefix
	V4Prefix = "v4Prefix"

	// V6Prefix is a IPv6 subnet/CIDR prefix
	V6Prefix = "v6Prefix"

	// Interface is an interface id/name on the system
	Interface = "interface"

	// Veth is a veth object or ID
	Veth = "veth"

	// VethPair is a tuple of Veth that are paired
	VethPair = "vethPair"

	// SHA is a sha of something
	SHA = "sha"

	// ServiceName is the orchestration framework name for a service
	ServiceName = "serviceName"

	// ServiceID is the orchestration unique ID of a service
	ServiceID = "serviceID"

	// CiliumNetworkPolicy is a cilium specific NetworkPolicy
	CiliumNetworkPolicy = "ciliumNetworkPolicy"

	// CiliumNetworkPolicyName is the name of a CiliumNetworkPolicy
	CiliumNetworkPolicyName = "ciliumNetworkPolicyName"

	// BPFMapKey is a key from a BPF map
	BPFMapKey = "bpfMapKey"

	// BPFMapValue is a value from a BPF map
	BPFMapValue = "bpfMapValue"

	// XDPDevice is the device name
	XDPDevice = "xdpDevice"

	// EndpointLabelSelector is a selector for Endpoints by label
	EndpointLabelSelector = "EndpointLabelSelector"

	// IdentityLabelSelector is a selector for Identities by label
	IdentityLabelSelector = "IdentityLabelSelector"

	// IdentitySelector is a selector for Endpoints
	EndpointSelector = "IdentitySelector"

	// Path is a filesystem path. It can be a file or directory.
	// Note: pkg/proxy/accesslog points to this variable so be careful when
	// changing the value
	Path = "file-path"

	// Object is used when "%+v" printing Go objects for debug or error handling.
	// It is often paired with logfields.Repr to render the object.
	Object = "obj"

	// Request is a request object received by us, reported in debug or error.
	// It is often paired with logfields.Repr to render the object.
	Request = "req"

	// Params are the parameters of a request, reported in debug or error.
	Params = "params"

	// Response is a response object received by us, reported in debug or error.
	// It is often paired with logfields.Repr to render the object.
	Response = "resp"

	// Route is a L2 or L3 Linux route
	Route = "route"

	// RetryUUID is an UUID identical for all retries of a set
	RetryUUID = "retryUUID"

	// Envoy xDS-protocol-specific

	// XDSStreamID is the ID of an xDS request stream.
	XDSStreamID = "xdsStreamID"

	// XDSVersionInfo is the version info of an xDS resource.
	XDSVersionInfo = "xdsVersionInfo"

	// XDSTypeURL is the URL that identifies an xDS resource type.
	XDSTypeURL = "xdsTypeURL"

	// XDSNonce is a nonce sent in xDS requests and responses.
	XDSNonce = "xdsNonce"

	// XDSCanary is a boolean indicating whether a response is a dry run.
	XDSCanary = "xdsCanary"

	// XDSResourceName is the name of an xDS resource.
	XDSResourceName = "xdsResourceName"

	// XDSClientNode is the ID of an XDS client, e.g. an Envoy node.
	XDSClientNode = "xdsClientNode"

	// K8s-specific

	// K8sNodeID is the k8s ID of a K8sNode
	K8sNodeID = "k8sNodeID"

	// K8sPodName is the name of a k8s pod
	K8sPodName = "k8sPodName"

	// K8sSvcName is the name of a K8s service
	K8sSvcName = "k8sSvcName"

	// K8sSvcType is the k8s service type (e.g. NodePort, Loadbalancer etc.)
	K8sSvcType = "k8sSvcType"

	// K8sEndpointName is the k8s name for a k8s Endpoint (not a cilium Endpoint)
	K8sEndpointName = "k8sEndpointName"

	// K8sNamespace is the namespace something belongs to
	K8sNamespace = "k8sNamespace"

	// K8sIdentityAnnotation is a k8s non-identifying annotations on k8s objects
	K8sIdentityAnnotation = "k8sIdentityAnnotation"

	// K8sNetworkPolicy is a k8s NetworkPolicy object (not a CiliumNetworkObject, above).
	K8sNetworkPolicy = "k8sNetworkPolicy"

	// K8sNetworkPolicyName is the name of a K8sPolicyObject
	K8sNetworkPolicyName = "k8sNetworkPolicyName"

	// K8sIngress is a k8s Ingress service object
	K8sIngress = "k8sIngress"

	// K8sIngressName is the name of a K8sIngress
	K8sIngressName = "k8sIngressName"

	// K8sAPIVersion is the version of the k8s API an object has
	K8sAPIVersion = "k8sApiVersion"

	// Attempt is the attempt number if an operation is attempted multiple times
	Attempt = "attempt"

	// TrafficDirection represents the directionality of traffic with respect
	// to an endpoint.
	TrafficDirection = "trafficDirection"
)
