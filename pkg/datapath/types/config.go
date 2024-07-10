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
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

// NodeNeighborEnqueuer provides an interface for clients to push node updates
// for further processing.
type NodeNeighborEnqueuer interface {
	// Enqueue enqueues a node for processing node neighbors updates.
	Enqueue(*nodeTypes.Node, bool)
}

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

	// GetIdentityLocked returns a globally-significant numeric security
	// identity while assuming that the backing data structure is locked.
	// This function should be removed in favour of GetIdentity()
	GetIdentityLocked() identity.NumericIdentity

	IPv4Address() netip.Addr
	IPv6Address() netip.Addr
	GetNodeMAC() mac.MAC
	GetIfIndex() int
	GetEndpointNetNsCookie() uint64
}

// CompileTimeConfiguration provides datapath implementations a clean interface
// to access endpoint-specific configuration that can only be changed at
// compile time.
type CompileTimeConfiguration interface {
	DeviceConfiguration

	// TODO: Move this detail into the datapath
	ConntrackLocalLocked() bool

	// RequireARPPassthrough returns true if the datapath must implement
	// ARP passthrough for this endpoint
	RequireARPPassthrough() bool

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

	// GetPolicyVerdictLogFilter returns the PolicyVerdictLogFilter for the endpoint
	GetPolicyVerdictLogFilter() uint32

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
func RemoteSNATDstAddrExclusionCIDRv4() *cidr.CIDR {
	if c := option.Config.GetIPv4NativeRoutingCIDR(); c != nil {
		// ipv4-native-routing-cidr is set, so use it
		return c
	}

	return node.GetIPv4AllocRange()
}

// RemoteSNATDstAddrExclusionCIDRv6 returns a IPv6 CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func RemoteSNATDstAddrExclusionCIDRv6() *cidr.CIDR {
	if c := option.Config.GetIPv6NativeRoutingCIDR(); c != nil {
		// ipv6-native-routing-cidr is set, so use it
		return c
	}

	return node.GetIPv6AllocRange()
}
