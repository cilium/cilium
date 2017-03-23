// Copyright 2016-2017 Authors of Cilium
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

package addressing

import (
	"net"
)

const (
	// DefaultIPv6Prefix is the prefix for all the IPv6 addresses.
	DefaultIPv6Prefix = "f00d::"
	// DefaultIPv6PrefixLen is the length used to allocate container IPv6 addresses from.
	DefaultIPv6PrefixLen = 112
	// DefaultIPv4Prefix is the prefix for all the IPv4 addresses.
	// %d is substituted with the last byte of first global IPv4 address
	// configured on the system.
	DefaultIPv4Prefix = "10.%d.0.1"
	// DefaultIPv4PrefixLen is the length used to allocate container IPv4 addresses from.
	DefaultIPv4PrefixLen = 16
	// DefaultIPv4ClusterPrefixLen is the IPv4 prefix length of the entire cluster.
	DefaultIPv4ClusterPrefixLen = 8
	// DefaultNAT46Prefix is the IPv6 prefix to represent NATed IPv4 addresses.
	DefaultNAT46Prefix = "0:0:0:0:0:FFFF::/96"
)

var (
	// Default addressing schema
	//
	// cluster:		    beef:beef:beef:beef::/64
	// node:                    beef:beef:beef:beef:<node>:<node>:/96
	// state:                   beef:beef:beef:beef:<node>:<node>:<state>:/112
	// lxc:                     beef:beef:beef:beef:<node>:<node>:<state>:<lxc>/128

	// ClusterIPv6Mask represents the CIDR Mask for an entire cluster.
	ClusterIPv6Mask = net.CIDRMask(64, 128)
	// NodeIPv6Mask represents the CIDR Mask for the cilium node.
	NodeIPv6Mask = net.CIDRMask(96, 128)
	// StateIPv6Mask represents the CIDR Mask for the state position.
	StateIPv6Mask = net.CIDRMask(112, 128)

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
)
