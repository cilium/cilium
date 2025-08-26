// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"net"
)

const (
	// DefaultIPv4Prefix is the prefix for all the IPv4 addresses.
	// %d is substituted with the last byte of first global IPv4 address
	// configured on the system.
	DefaultIPv4Prefix = "10.%d.0.1"

	// DefaultIPv4PrefixLen is the length used to allocate container IPv4 addresses from.
	DefaultIPv4PrefixLen = 16

	// HostDevice is the name of the device that connects the cilium IP
	// space with the host's networking model
	HostDevice = "cilium_host"

	// SecondHostDevice is the name of the second interface of the host veth pair.
	SecondHostDevice = "cilium_net"

	// IPIPv4Device is a device of type 'ipip', created by the agent.
	IPIPv4Device = "cilium_ipip4"

	// IPIPv6Device is a device of type 'ip6tnl', created by the agent.
	IPIPv6Device = "cilium_ipip6"

	// GeneveDevice is a device of type 'geneve', created by the agent.
	GeneveDevice = "cilium_geneve"

	// VxlanDevice is a device of type 'vxlan', created by the agent.
	VxlanDevice = "cilium_vxlan"

	// CiliumK8sAnnotationPrefix is the prefix key for the annotations used in kubernetes.
	CiliumK8sAnnotationPrefix = "cilium.io/"

	// AgentNotReadyNodeTaint is a node taint which prevents pods from being
	// scheduled. Once cilium is setup it is removed from the node. Mostly
	// used in cloud providers to prevent existing CNI plugins from managing
	// pods.
	AgentNotReadyNodeTaint = "node." + CiliumK8sAnnotationPrefix + "agent-not-ready"
)

var (
	// Default addressing schema
	//
	// node:                    beef:beef:beef:beef:<node>:<node>:/96
	// lxc:                     beef:beef:beef:beef:<node>:<node>::<lxc>/128

	// ContainerIPv6Mask is the IPv6 prefix length for address assigned to
	// container. The default is L3 only and thus /128.
	ContainerIPv6Mask = net.CIDRMask(128, 128)

	// ContainerIPv4Mask is the IPv4 prefix length for address assigned to
	// container. The default is L3 only and thus /32.
	ContainerIPv4Mask = net.CIDRMask(32, 32)

	// IPv6DefaultRoute is the default IPv6 route.
	IPv6DefaultRoute = net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

	// IPv4DefaultRoute is the default IPv4 route.
	IPv4DefaultRoute = net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}

	// ExcludedDevicePrefixes are prefixes that we don't consider during automatic device detection.
	ExcludedDevicePrefixes = []string{
		"cilium_",
		"lo",
		"lxc",
		"cni",
		"docker",
	}
)
