// Copyright 2019-2020 Authors of Cilium
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

package datapath

import (
	"io"

	"github.com/cilium/cilium/pkg/addressing"
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
	// GetCIDRPrefixLengths fetches the lists of unique IPv6 and IPv4
	// prefix lengths used for datapath lookups, each of which is sorted
	// from longest prefix to shortest prefix. It must return more than
	// one element in each returned array.
	GetCIDRPrefixLengths() (s6, s4 []int)

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

	IPv4Address() addressing.CiliumIPv4
	IPv6Address() addressing.CiliumIPv6
	GetNodeMAC() mac.MAC
}

// CompileTimeConfiguration provides datapath implementations a clean interface
// to access endpoint-specific configuration that can only be changed at
// compile time.
type CompileTimeConfiguration interface {
	DeviceConfiguration

	// TODO: Move this detail into the datapath
	HasIpvlanDataPath() bool
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
	WriteNetdevConfig(io.Writer, DeviceConfiguration) error

	// WriteTemplateConfig writes the implementation-specific configuration
	// of configurable options for BPF templates to the specified writer.
	WriteTemplateConfig(w io.Writer, cfg EndpointConfiguration) error

	// WriteEndpointConfig writes the implementation-specific configuration
	// of configurable options for the endpoint to the specified writer.
	WriteEndpointConfig(w io.Writer, cfg EndpointConfiguration) error
}

// RemoteSNATDstAddrExclusionCIDRv4 returns a CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func RemoteSNATDstAddrExclusionCIDRv4() *cidr.CIDR {
	if c := option.Config.IPv4NativeRoutingCIDR(); c != nil {
		// native-routing-cidr is set, so use it
		return c
	}

	return node.GetIPv4AllocRange()
}

// RemoteSNATDstAddrExclusionCIDRv6 returns a IPv6 CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func RemoteSNATDstAddrExclusionCIDRv6() *cidr.CIDR {
	return node.GetIPv6AllocRange()
}
