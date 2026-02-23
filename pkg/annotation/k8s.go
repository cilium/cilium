// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

import (
	"regexp"
)

const (
	// Prefix is the common prefix for all annotations
	Prefix = "io.cilium"

	// ConfigPrefix is the common prefix for configuration related annotations.
	ConfigPrefix = "config.cilium.io"

	// ClusterMeshPrefix is the common prefix for ClusterMesh related annotations.
	ClusterMeshPrefix = "clustermesh.cilium.io"

	// IngressPrefix is the common prefix for ingress related annotations.
	IngressPrefix = "ingress.cilium.io"

	// NetworkPrefix is the common prefix for network related annotations.
	NetworkPrefix = "network.cilium.io"

	// PolicyPrefix is the common prefix for policy related annotations.
	PolicyPrefix = "policy.cilium.io"

	// ServicePrefix is the common prefix for service related annotations.
	ServicePrefix = "service.cilium.io"

	// IPAMPrefix is the common prefix for IPAM related annotations.
	IPAMPrefix = "ipam.cilium.io"

	// LBIPAMPrefix is the common prefix for LB IPAM related annotations.
	LBIPAMPrefix = "lbipam.cilium.io"

	// CNIPrefix is the common prefix for CNI related annotations.
	CNIPrefix = "cni.cilium.io"

	// CECPrefix is the common prefix for CEC related annotations.
	CECPrefix = "cec.cilium.io"

	// PodAnnotationMAC is used to store the MAC address of the Pod.
	PodAnnotationMAC = CNIPrefix + "/mac-address"

	// PolicyName / PolicyNameAlias is an optional annotation to the NetworkPolicy
	// resource which specifies the name of the policy node to which all
	// rules should be applied to.
	PolicyName      = PolicyPrefix + "/name"
	PolicyNameAlias = Prefix + ".name"

	// V4CIDRName / V4CIDRNameAlias is the annotation name used to store the IPv4
	// pod CIDR in the node's annotations.
	V4CIDRName      = NetworkPrefix + "/ipv4-pod-cidr"
	V4CIDRNameAlias = Prefix + ".network.ipv4-pod-cidr"
	// V6CIDRName / V6CIDRNameAlias is the annotation name used to store the IPv6
	// pod CIDR in the node's annotations.
	V6CIDRName      = NetworkPrefix + "/ipv6-pod-cidr"
	V6CIDRNameAlias = Prefix + ".network.ipv6-pod-cidr"

	// V4HealthName / V4HealthNameAlias is the annotation name used to store the
	// IPv4 address of the cilium-health endpoint in the node's annotations.
	V4HealthName      = NetworkPrefix + "/ipv4-health-ip"
	V4HealthNameAlias = Prefix + ".network.ipv4-health-ip"
	// V6HealthName / V6HealthNameAlias is the annotation name used to store the
	// IPv6 address of the cilium-health endpoint in the node's annotations.
	V6HealthName      = NetworkPrefix + "/ipv6-health-ip"
	V6HealthNameAlias = Prefix + ".network.ipv6-health-ip"

	// V4IngressName / V4IngressNameAlias is the annotation name used to store
	// the IPv4 address of the Ingress listener in the node's annotations.
	V4IngressName      = NetworkPrefix + "/ipv4-Ingress-ip"
	V4IngressNameAlias = Prefix + ".network.ipv4-Ingress-ip"
	// V6IngressName / V6IngressNameAlias is the annotation name used to store
	// the IPv6 address of the Ingress listener in the node's annotations.
	V6IngressName      = NetworkPrefix + "/ipv6-Ingress-ip"
	V6IngressNameAlias = Prefix + ".network.ipv6-Ingress-ip"

	// CiliumHostIP / CiliumHostIPAlias is the annotation name used to store the
	// IPv4 address of the cilium host interface in the node's annotations.
	CiliumHostIP      = NetworkPrefix + "/ipv4-cilium-host"
	CiliumHostIPAlias = Prefix + ".network.ipv4-cilium-host"

	// CiliumHostIPv6 / CiliumHostIPv6Alias is the annotation name used to store
	// the IPv6 address of the cilium host interface in the node's annotation.
	CiliumHostIPv6      = NetworkPrefix + "/ipv6-cilium-host"
	CiliumHostIPv6Alias = Prefix + ".network.ipv6-cilium-host"

	// CiliumEncryptionKey / CiliumEncryptionKeyAlias is the annotation name used to
	// store the encryption key of the cilium host interface in the node's annotation.
	CiliumEncryptionKey      = NetworkPrefix + "/encryption-key"
	CiliumEncryptionKeyAlias = Prefix + ".network.encryption-key"

	// GlobalService / GlobalServiceAlias if set to true, marks a service to
	// become a global service.
	GlobalService      = ServicePrefix + "/global"
	GlobalServiceAlias = Prefix + "/global-service"

	// GlobalServiceSyncEndpointSlice if set to true, marks a service to
	// synchronize remote clusters endpoint slices to the local Kubernetes API
	GlobalServiceSyncEndpointSlices = ServicePrefix + "/global-sync-endpoint-slices"

	// SharedService / SharedServiceAlias if set to false, prevents a service
	// from being shared, the default is true if GlobalService is set, otherwise
	// false. Setting the annotation SharedService to false while setting
	// GlobalService to true allows to expose remote endpoints without
	// sharing local endpoints.
	SharedService      = ServicePrefix + "/shared"
	SharedServiceAlias = Prefix + "/shared-service"

	// ServiceAffinity / ServiceAffinityAlias annotations determines the
	// preferred endpoint destination.
	// Allowed values:
	//  - local
	//		preferred endpoints from local cluster if available
	//  - remote
	// 		preferred endpoints from remote cluster if available
	//  - none (default)
	//		no preference. Default behavior if this annotation does not exist
	ServiceAffinity      = ServicePrefix + "/affinity"
	ServiceAffinityAlias = Prefix + "/service-affinity"

	// CoreDNSAutoPatched is the annotation used to roll out CoreDNS once we
	// we have patched its configuration to enabled MCS-API support.
	CoreDNSAutoPatched = ClusterMeshPrefix + "/autoPatchedAt"

	// SupportedIPFamilies is an internal annotation in MCS-API to track which
	// ip families are used and supported by the local cluster
	SupportedIPFamilies = ClusterMeshPrefix + "/supported-ip-families"

	// ServiceLoadBalancingAlgorithm indicates which backend selection algorithm
	// for a given Service to use. This annotation will override the default
	// value set in bpf-lb-algorithm.
	// Allowed values:
	// - random
	// - maglev
	ServiceLoadBalancingAlgorithm = ServicePrefix + "/lb-algorithm"

	// ServiceNodeExposure is the label name used to mark a service to only a
	// subset of the nodes which match the same value. For all other nodes, this
	// service is ignored and not installed into their datapath.
	ServiceNodeExposure = ServicePrefix + "/node"

	// ServiceNodeSelectorExposure is the label name used to mark a service to only a
	// subset of the nodes which match the label selector. For all other nodes, this
	// service is ignored and not installed into their datapath.
	ServiceNodeSelectorExposure = ServicePrefix + "/node-selector"

	// ServiceTypeExposure is the annotation name used to mark what service type
	// to provision (only single type is allowed; allowed types: "ClusterIP",
	// "NodePort" and "LoadBalancer").
	//
	// For example, a LoadBalancer service includes ClusterIP and NodePort (unless
	// allocateLoadBalancerNodePorts is set to false). To avoid provisioning
	// the latter two, one can set the annotation with the value "LoadBalancer".
	ServiceTypeExposure = ServicePrefix + "/type"

	// ServiceSourceRangesPolicy is the annotation name used to specify the policy
	// of the user-provided loadBalancerSourceRanges, meaning whether this CIDR
	// list should act as an allow- or deny-list. Both "allow" or "deny" are
	// possible values for this annotation.
	ServiceSourceRangesPolicy = ServicePrefix + "/src-ranges-policy"

	// ServiceProxyDelegation is the annotation name used to specify whether there
	// should be delegation to a 3rd party proxy. Allowed values are "none" (default)
	// and "delegate-if-local". The latter pushes all service packets to a user
	// space proxy if the selected backend IP is the IP of the local node. If the
	// selected backend IP is non-local then the BPF datapath forwards the packet
	// back out again with the configured BPF load-balancing mechanism.
	ServiceProxyDelegation = ServicePrefix + "/proxy-delegation"

	// ServiceForwardingMode annotations determines the way packets are pushed to the
	// remote backends.
	// Allowed values are of type loadbalancer.SVCForwardingMode:
	//  - dsr
	//		use the configured DSR method
	//  - snat
	//		use SNAT so that reply traffic comes back
	ServiceForwardingMode = ServicePrefix + "/forwarding-mode"

	// NoTrack / NoTrackAlias is the annotation name used to store the port and
	// protocol that we should bypass kernel conntrack for a given pod. This
	// applies for both TCP and UDP connection. Current use case is NodeLocalDNS.
	NoTrack      = PolicyPrefix + "/no-track-port"
	NoTrackAlias = Prefix + ".no-track-port"

	// WireguardPubKey / WireguardPubKeyAlias is the annotation name used to store
	// the WireGuard public key in the CiliumNode CRD that we need to use to encrypt
	// traffic to that node.
	WireguardPubKey      = NetworkPrefix + "/wg-pub-key"
	WireguardPubKeyAlias = Prefix + ".network.wg-pub-key"

	// BGPVRouterAnnoPrefix is the prefix used for all Virtual Router annotations
	// Its just a prefix, because the ASN of the Router is part of the annotation itself
	BGPVRouterAnnoPrefix = "cilium.io/bgp-virtual-router."

	// IPAMPoolKey is the annotation name used to store the IPAM pool name from
	// which workloads should allocate their IP from
	IPAMPoolKey = IPAMPrefix + "/ip-pool"

	// IPAMIPv4PoolKey is the annotation name used to store the IPAM IPv4 pool name from
	// which workloads should allocate their IP from
	IPAMIPv4PoolKey = IPAMPrefix + "/ipv4-pool"

	// IPAMIPv6PoolKey is the annotation name used to store the IPAM IPv6 pool name from
	// which workloads should allocate their IP from
	IPAMIPv6PoolKey = IPAMPrefix + "/ipv6-pool"

	// IPAMIgnore is the annotation used to make the Cilium operator IPAM logic
	// ignore the given CiliumNode object
	IPAMIgnore = IPAMPrefix + "/ignore"

	// IPAMRequirePoolMatch is the annotation used to prevent fallback to the
	// default pool when no pool selectors match. Can be set on pods or namespaces.
	IPAMRequirePoolMatch = IPAMPrefix + "/require-pool-match"

	// IPAMSkipMasquerade indicates whether the datapath should avoid masquerading
	// connections from this IP pool when the cluster is in tunneling mode.
	IPAMSkipMasquerade = IPAMPrefix + "/skip-masquerade"

	LBIPAMIPsKey     = LBIPAMPrefix + "/ips"
	LBIPAMIPKeyAlias = Prefix + "/lb-ipam-ips"

	LBIPAMSharingKey                  = LBIPAMPrefix + "/sharing-key"
	LBIPAMSharingKeyAlias             = Prefix + "/lb-ipam-sharing-key"
	LBIPAMSharingAcrossNamespace      = LBIPAMPrefix + "/sharing-cross-namespace"
	LBIPAMSharingAcrossNamespaceAlias = Prefix + "/lb-ipam-sharing-cross-namespace"

	CECInjectCiliumFilters      = CECPrefix + "/inject-cilium-filters"
	CECIsL7LB                   = CECPrefix + "/is-l7lb"
	CECUseOriginalSourceAddress = CECPrefix + "/use-original-source-address"

	NoTrackHostPorts = NetworkPrefix + "/no-track-host-ports"

	// GlobalNamespace is the annotation used to mark namespaces for global export in ClusterMesh.
	GlobalNamespace = ClusterMeshPrefix + "/global"

	// FIBTableID is the annotation used to specify the FIB table ID for egress routing.
	FIBTableID = NetworkPrefix + "/fib-table-id"
)

// CiliumPrefixRegex is a regex matching Cilium specific annotations.
var CiliumPrefixRegex = regexp.MustCompile(`^([A-Za-z0-9]+\.)*cilium.io/`)

type annotatedObject interface {
	GetAnnotations() map[string]string
}

// Get returns the annotation value associated with the given key, or any of
// the additional aliases if not found.
func Get(obj annotatedObject, key string, aliases ...string) (value string, ok bool) {
	keys := append([]string{key}, aliases...)
	annotations := obj.GetAnnotations()
	for _, k := range keys {
		if value, ok = annotations[k]; ok {
			return value, ok
		}
	}

	return "", false
}
