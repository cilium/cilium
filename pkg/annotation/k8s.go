// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

const (
	// Prefix is the common prefix for all annotations
	Prefix = "io.cilium"

	// Name is an optional annotation to the NetworkPolicy
	// resource which specifies the name of the policy node to which all
	// rules should be applied to.
	Name = Prefix + ".name"

	// V4CIDRName is the annotation name used to store the IPv4
	// pod CIDR in the node's annotations.
	V4CIDRName = Prefix + ".network.ipv4-pod-cidr"
	// V6CIDRName is the annotation name used to store the IPv6
	// pod CIDR in the node's annotations.
	V6CIDRName = Prefix + ".network.ipv6-pod-cidr"

	// V4HealthName is the annotation name used to store the IPv4
	// address of the cilium-health endpoint in the node's annotations.
	V4HealthName = Prefix + ".network.ipv4-health-ip"
	// V6HealthName is the annotation name used to store the IPv6
	// address of the cilium-health endpoint in the node's annotations.
	V6HealthName = Prefix + ".network.ipv6-health-ip"

	// V4IngressName is the annotation name used to store the IPv4
	// address of the Ingress listener in the node's annotations.
	V4IngressName = Prefix + ".network.ipv4-Ingress-ip"
	// V6IngressName is the annotation name used to store the IPv6
	// address of the Ingress listener in the node's annotations.
	V6IngressName = Prefix + ".network.ipv6-Ingress-ip"

	// CiliumHostIP is the annotation name used to store the IPv4 address
	// of the cilium host interface in the node's annotations.
	CiliumHostIP = Prefix + ".network.ipv4-cilium-host"

	// CiliumHostIPv6 is the annotation name used to store the IPv6 address
	// of the cilium host interface in the node's annotation.
	CiliumHostIPv6 = Prefix + ".network.ipv6-cilium-host"

	// CiliumEncryptionKey is the annotation name used to store the encryption
	// key of the cilium host interface in the node's annotation.
	CiliumEncryptionKey = Prefix + ".network.encryption-key"

	// GlobalService if set to true, marks a service to become a global
	// service
	GlobalService = Prefix + "/global-service"

	// SharedService if set to false, prevents a service from being shared,
	// the default is true if GlobalService is set, otherwise false,
	// Setting the annotation SharedService to false while setting
	// GlobalService to true allows to expose remote endpoints without
	// sharing local endpoints.
	SharedService = Prefix + "/shared-service"

	// ProxyVisibility is the annotation name used to indicate whether proxy
	// visibility should be enabled for a given pod (i.e., all traffic for the
	// pod is redirected to the proxy for the given port / protocol in the
	// annotation
	ProxyVisibility = Prefix + ".proxy-visibility"

	// NoTrack is the annotation name used to store the port and protocol
	// that we should bypass kernel conntrack for a given pod. This applies for
	// both TCP and UDP connection. Current use case is NodeLocalDNS.
	NoTrack = Prefix + ".no-track-port"

	// WireguardPubKey is the annotation name used to store the Wireguard
	// public key in the CiliumNode CRD that we need to use to encrypt traffic
	// to that node.
	WireguardPubKey = Prefix + ".network.wg-pub-key"
)
