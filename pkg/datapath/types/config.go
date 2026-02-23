// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"io"
	"net/netip"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// DeviceConfiguration is an interface for injecting configuration of datapath
// options that affect lookups and logic applied at a per-device level, whether
// those are devices associated with the endpoint or associated with the host.
type DeviceConfiguration interface {
	// GetOptions fetches the configurable datapath options from the owner.
	GetOptions() *option.IntOptions
}

// LoadTimeConfiguration provides datapath implementations a clean interface
// to access endpoint-specific configuration that can be changed at load time.
type LoadTimeConfiguration interface {
	// GetID returns a locally-significant endpoint identification number.
	GetID() uint64
	// StringID returns the string-formatted version of the ID from GetID().
	StringID() string
	// GetIdentity returns a globally-significant numeric security identity.
	GetIdentity() identity.NumericIdentity

	IPv4Address() netip.Addr
	IPv6Address() netip.Addr
	GetNodeMAC() mac.MAC
	GetIfIndex() int
	GetEndpointNetNsCookie() uint64

	// GetPolicyVerdictLogFilter returns the PolicyVerdictLogFilter for the endpoint
	GetPolicyVerdictLogFilter() uint32

	// GetPropertyValue returns the endpoint property value for this key.
	GetPropertyValue(key string) any

	GetFibTableID() uint32

	// RequireARPPassthrough returns true if the datapath must implement
	// ARP passthrough for this endpoint
	RequireARPPassthrough() bool
}

// CompileTimeConfiguration provides datapath implementations a clean interface
// to access endpoint-specific configuration that can only be changed at
// compile time.
type CompileTimeConfiguration interface {
	DeviceConfiguration

	// RequireEgressProg returns true if the endpoint requires an egress
	// program attached to the InterfaceName() invoking the section
	// "to-container"
	RequireEgressProg() bool

	// RequireRouting returns true if the endpoint requires BPF routing to
	// be enabled, when disabled, routing is delegated to Linux routing
	RequireRouting() bool

	// RequireEndpointRoute returns true if the endpoint wishes to have a
	// per endpoint route installed in the host's routing table to point to
	// the endpoint's interface
	RequireEndpointRoute() bool

	// IsHost returns true if the endpoint is the host endpoint.
	IsHost() bool
}

// EndpointConfiguration provides datapath implementations a clean interface
// to access endpoint-specific configuration when configuring the datapath.
type EndpointConfiguration interface {
	CompileTimeConfiguration
	LoadTimeConfiguration
}

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
	WriteTemplateConfig(w io.Writer, nodeCfg *LocalNodeConfiguration, cfg EndpointConfiguration) error

	// WriteEndpointConfig writes the implementation-specific configuration
	// of configurable options for the endpoint to the specified writer.
	WriteEndpointConfig(w io.Writer, nodeCfg *LocalNodeConfiguration, cfg EndpointConfiguration) error
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
