// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"io"

	"github.com/cilium/cilium/pkg/cidr"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// ConfigWriter is anything which writes the configuration for various datapath
// program types.
type ConfigWriter interface {
	// WriteNodeConfig writes the implementation-specific configuration of
	// node-wide options into the specified writer.
	WriteNodeConfig(io.Writer, *LocalNodeConfiguration) error

	// WriteNetdevConfig writes the implementation-specific configuration
	// of configurable options to the specified writer. Options specified
	// here will apply to base programs and not to endpoints, though
	// endpoints may have equivalent configurable options.
	WriteNetdevConfig(io.Writer, *option.IntOptions) error

	// WriteTemplateConfig writes the implementation-specific configuration
	// of configurable options for BPF templates to the specified writer.
	WriteTemplateConfig(w io.Writer, nodeCfg *LocalNodeConfiguration, cfg endpoint.Config) error

	// WriteEndpointConfig writes the implementation-specific configuration
	// of configurable options for the endpoint to the specified writer.
	WriteEndpointConfig(w io.Writer, nodeCfg *LocalNodeConfiguration, cfg endpoint.Config) error
}

// RemoteSNATDstAddrExclusionCIDRv4 returns a CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func RemoteSNATDstAddrExclusionCIDRv4(localNode node.LocalNode) *cidr.CIDR {
	if localNode.Local.IPv4NativeRoutingCIDR != nil {
		// ipv4-native-routing-cidr is set or has been autodetected, so use it
		return localNode.Local.IPv4NativeRoutingCIDR
	}

	return localNode.IPv4AllocCIDR
}

// RemoteSNATDstAddrExclusionCIDRv6 returns a IPv6 CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func RemoteSNATDstAddrExclusionCIDRv6(localNode node.LocalNode) *cidr.CIDR {
	if localNode.Local.IPv6NativeRoutingCIDR != nil {
		// ipv6-native-routing-cidr is set or has been autodetected, so use it
		return localNode.Local.IPv6NativeRoutingCIDR
	}

	return localNode.IPv6AllocCIDR
}
