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

	// EndpointID is the numeric endpoint identifier
	EndpointID = "endpointID"

	// ContainerID is the container identifier
	ContainerID = "containerID"

	// IdentityLabels are the labels relevant for the security identity
	IdentityLabels = "identityLabels"

	// Identity is the identifier of a security identity
	Identity = "identity"

	// PolicyID is the identifier of a L3, L4 or L7 Policy. Ideally the .NumericIdentity
	PolicyID = "policyID"

	// L3PolicyID is the identifier of a L3 Policy
	L3PolicyID = "policyID.L3"

	// L4PolicyID is the identifier of a L4 Policy
	L4PolicyID = "PolicyID.L4"

	// Path is a filesystem path. It can be a file or directory
	// REVIEW Should this match pkg/proxy/accesslog.FieldFilePath ?
	Path = "path"

	// IPAddr is an IPV4 or IPv6 address
	IPAddr = "ipAddr"

	// Port is a L4 port
	Port = "port"

	// Protocol is the L4 protocol
	Protocol = "protocol"

	// V4Prefix is a IPv4 subnet/CIDR prefix
	V4Prefix = "v4Prefix"

	// L4Addr is a L4 address object (IP, port and protocol)
	L4Addr = "l4Addr"

	// L4AddreID is the ID of a L4 address
	L4AddrID = "l4AddrID"

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

	ServiceNamespace = "serviceNamespace"
	ServiceType      = "serviceType"
	ServiceID        = "serviceID"
	ServicePortID    = "servicePortID"
	Service          = "service"
	LBBackend        = "lbBackend"

	CiliumNetworkPolicyName = "ciliumNetworkPolicyName"
	CiliumNetworkPolicy     = "ciliumNetworkPolicy"

	CiliumNode     = "ciliumNode"
	CiliumID       = "ciliumNodeID"
	CiliumRuleName = "ciliumRuleName"

	BPFMapKey   = "bpfMapKey"
	BPFMapValue = "bpfMapValue"
	BPFFilter   = "bpfFilter"

	K8sNode               = "ciliumNode"
	K8sNodeID             = "ciliumNodeID"
	K8sPodName            = "k8sPodName"
	K8sSvcName            = "k8sSvcName"
	K8sSvcType            = "k8sSvcType"
	K8sEndpointName       = "k8sEndpointName"
	K8sNamespace          = "k8sNamespace"
	K8sIdentityAnnotation = "k8sIdentityAnnotation" // REVIEW Reconcile this with orchestrationLabels
	K8sNetworkPolicyName  = "k8sNetworkPolicyName"
	K8sNetworkPolicy      = "k8sNetworkPolicy"
	K8sIngress            = "k8sIngress"
	K8sIngressName        = "k8sIngressName"
	K8sLabels             = "k8sLabels"

	// REVIEW to pkg/policy?
	PolicyEndpointSelector = "policyEndpointSelector"
	PolicyLabelSelector    = "policyLabelSelector"
)
