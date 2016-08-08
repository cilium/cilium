package addressing

import (
	"net"
)

const (
	// Default prefix for all IPv6 addresses.
	DefaultIPv6Prefix = "f00d::"
	// Prefix length to allocate container IPv6 addresses from
	DefaultIPv6PrefixLen = 112
	// Default prefix for all IPv4 addresses. %d is substituted with the
	// last byte of first global IPv4 address configured on the system.
	DefaultIPv4Prefix = "10.%d.0.1"
	// Prefix length to allocate container IPv4 addresses from
	DefaultIPv4PrefixLen = 16
	// Default IPv4 prefix length of entire cluster
	DefaultIPv4ClusterPrefixLen = 8
	// Default IPv6 prefix to represent NATed IPv4 addresses
	DefaultNAT46Prefix = "aa46::/48"
)

var (
	// Default addressing schema
	//
	// cluster:		    beef:beef:beef:beef::/64
	// node:                    beef:beef:beef:beef:<node>:<node>:/96
	// state:                   beef:beef:beef:beef:<node>:<node>:<state>:/112
	// lxc:                     beef:beef:beef:beef:<node>:<node>:<state>:<lxc>/128

	// ClusterIPv6Mask represents the CIDR Mask for an entire cluster
	ClusterIPv6Mask = net.CIDRMask(64, 128)
	// NodeIPv6Mask represents the CIDR Mask for the cilium node.
	NodeIPv6Mask = net.CIDRMask(96, 128)
	// StateIPv6Mask represents the CIDR Mask for the state position.
	StateIPv6Mask = net.CIDRMask(112, 128)

	// IPv6 prefix length for address assigned to container. The default is
	// L3 only and thus /128.
	ContainerIPv6Mask = net.CIDRMask(128, 128)
	// IPv4 prefix length for address assigned to container. The default is
	// L3 only and thus /32
	ContainerIPv4Mask = net.CIDRMask(32, 32)

	IPv6DefaultRoute = net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	IPv4DefaultRoute = net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
)
