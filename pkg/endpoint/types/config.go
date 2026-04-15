// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// Config provides datapath implementations a clean interface to access
// endpoint-specific configuration when configuring the datapath.
type Config interface {
	CompileTimeConfig
	LoadTimeConfig
}

// DeviceConfig is an interface for injecting configuration of datapath options
// that affect lookups and logic applied at a per-device level, whether those
// are devices associated with the endpoint or associated with the host.
type DeviceConfig interface {
	// GetOptions fetches the configurable datapath options from the owner.
	GetOptions() *option.IntOptions
}

// LoadTimeConfig provides datapath implementations a clean interface to access
// endpoint-specific configuration that can be changed at load time.
type LoadTimeConfig interface {
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

	// GetRTInfo returns the routing domain info for the pod.
	GetRTInfo() uint32

	// RequireARPPassthrough returns true if the datapath must implement
	// ARP passthrough for this endpoint
	RequireARPPassthrough() bool
}

// CompileTimeConfig provides datapath implementations a clean interface to
// access endpoint-specific configuration that can only be changed at compile
// time.
type CompileTimeConfig interface {
	DeviceConfig

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
