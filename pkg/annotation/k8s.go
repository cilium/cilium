// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	// Prefix is the common prefix for all annotations
	Prefix = "io.cilium"

	// NetworkPrefix is the common prefix for network related annotations.
	NetworkPrefix = "network.cilium.io"

	// ServicePrefix is the common prefix for service related annotations.
	ServicePrefix = "service.cilium.io"

	// Name is an optional annotation to the NetworkPolicy
	// resource which specifies the name of the policy node to which all
	// rules should be applied to.
	Name = Prefix + ".name"

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

	// ProxyVisibility is the annotation name used to indicate whether proxy
	// visibility should be enabled for a given pod (i.e., all traffic for the
	// pod is redirected to the proxy for the given port / protocol in the
	// annotation
	ProxyVisibility = Prefix + ".proxy-visibility"

	// NoTrack is the annotation name used to store the port and protocol
	// that we should bypass kernel conntrack for a given pod. This applies for
	// both TCP and UDP connection. Current use case is NodeLocalDNS.
	NoTrack = Prefix + ".no-track-port"

	// WireguardPubKey / WireguardPubKeyAlias is the annotation name used to store
	// the Wireguard public key in the CiliumNode CRD that we need to use to encrypt
	// traffic to that node.
	WireguardPubKey      = NetworkPrefix + "/wg-pub-key"
	WireguardPubKeyAlias = Prefix + ".network.wg-pub-key"
)

// Get returns the annotation value associated with the given key, or any of
// the additional aliases if not found.
func Get(obj metav1.Object, key string, aliases ...string) (value string, ok bool) {
	keys := append([]string{key}, aliases...)
	for _, k := range keys {
		if value, ok = obj.GetAnnotations()[k]; ok {
			return value, ok
		}
	}

	return "", false
}
