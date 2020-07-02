// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import (
	"fmt"

	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

// epInfoCache describes the set of lxcmap entries necessary to describe an Endpoint
// in the BPF maps. It is generated while holding the Endpoint lock, then used
// after releasing that lock to push the entries into the datapath.
// Functions below implement the EndpointFrontend interface with this cached information.
type epInfoCache struct {
	// revision is used by the endpoint regeneration code to determine
	// whether this cache is out-of-date wrt the underlying endpoint.
	revision uint64

	// For datapath.loader.endpoint
	epdir  string
	id     uint64
	ifName string
	ipvlan bool

	// For datapath.EndpointConfiguration
	identity                               identity.NumericIdentity
	mac                                    mac.MAC
	ipv4                                   addressing.CiliumIPv4
	ipv6                                   addressing.CiliumIPv6
	conntrackLocal                         bool
	requireARPPassthrough                  bool
	requireEgressProg                      bool
	requireRouting                         bool
	requireEndpointRoute                   bool
	policyVerdictLogFilter                 uint32
	cidr4PrefixLengths, cidr6PrefixLengths []int
	options                                *option.IntOptions
	lxcMAC                                 mac.MAC
	ifIndex                                int

	// endpoint is used to get the endpoint's logger.
	//
	// Do NOT use this for fetching endpoint data directly; this structure
	// is intended as a safe cache of endpoint data that is assembled while
	// holding the endpoint lock, for use beyond the holding of that lock.
	// Dereferencing fields in this endpoint is not guaranteed to be safe.
	endpoint *Endpoint
}

// Must be called when endpoint is still locked.
func (e *Endpoint) createEpInfoCache(epdir string) *epInfoCache {
	cidr6, cidr4 := e.GetCIDRPrefixLengths()

	ep := &epInfoCache{
		revision: e.nextPolicyRevision,

		epdir:                  epdir,
		id:                     e.GetID(),
		ifName:                 e.ifName,
		ipvlan:                 e.HasIpvlanDataPath(),
		identity:               e.getIdentity(),
		mac:                    e.GetNodeMAC(),
		ipv4:                   e.IPv4Address(),
		ipv6:                   e.IPv6Address(),
		conntrackLocal:         e.ConntrackLocalLocked(),
		requireARPPassthrough:  e.RequireARPPassthrough(),
		requireEgressProg:      e.RequireEgressProg(),
		requireRouting:         e.RequireRouting(),
		requireEndpointRoute:   e.RequireEndpointRoute(),
		policyVerdictLogFilter: e.GetPolicyVerdictLogFilter(),
		cidr4PrefixLengths:     cidr4,
		cidr6PrefixLengths:     cidr6,
		options:                e.Options.DeepCopy(),
		lxcMAC:                 e.mac,
		ifIndex:                e.ifIndex,

		endpoint: e,
	}
	return ep
}

func (ep *epInfoCache) GetIfIndex() int {
	return ep.ifIndex
}

func (ep *epInfoCache) LXCMac() mac.MAC {
	return ep.lxcMAC
}

// InterfaceName returns the name of the link-layer interface used for
// communicating with the endpoint.
func (ep *epInfoCache) InterfaceName() string {
	return ep.ifName
}

// MapPath returns tail call map path
func (ep *epInfoCache) MapPath() string {
	return ep.endpoint.BPFIpvlanMapPath()
}

// GetID returns the endpoint's ID.
func (ep *epInfoCache) GetID() uint64 {
	return ep.id
}

// StringID returns the endpoint's ID in a string.
func (ep *epInfoCache) StringID() string {
	return fmt.Sprintf("%d", ep.id)
}

// GetIdentity returns the security identity of the endpoint.
func (ep *epInfoCache) GetIdentity() identity.NumericIdentity {
	return ep.identity
}

// GetIdentityLocked returns the security identity of the endpoint.
func (ep *epInfoCache) GetIdentityLocked() identity.NumericIdentity {
	return ep.identity
}

// Logger returns the logger for the endpoint that is being cached.
func (ep *epInfoCache) Logger(subsystem string) *logrus.Entry {
	return ep.endpoint.Logger(subsystem)
}

// HasIpvlanDataPath returns whether the endpoint's datapath is implemented via ipvlan.
func (ep *epInfoCache) HasIpvlanDataPath() bool {
	return ep.ipvlan
}

// IPv4Address returns the cached IPv4 address for the endpoint.
func (ep *epInfoCache) IPv4Address() addressing.CiliumIPv4 {
	return ep.ipv4
}

// IPv6Address returns the cached IPv6 address for the endpoint.
func (ep *epInfoCache) IPv6Address() addressing.CiliumIPv6 {
	return ep.ipv6
}

// StateDir returns the directory for the endpoint's (next) state.
func (ep *epInfoCache) StateDir() string    { return ep.epdir }
func (ep *epInfoCache) GetNodeMAC() mac.MAC { return ep.mac }

func (ep *epInfoCache) ConntrackLocalLocked() bool {
	return ep.conntrackLocal
}

func (ep *epInfoCache) GetCIDRPrefixLengths() ([]int, []int) {
	return ep.cidr6PrefixLengths, ep.cidr4PrefixLengths
}

func (ep *epInfoCache) GetOptions() *option.IntOptions {
	return ep.options
}

// RequireARPPassthrough returns true if the datapath must implement ARP
// passthrough for this endpoint
func (ep *epInfoCache) RequireARPPassthrough() bool {
	return ep.requireARPPassthrough
}

// RequireEgressProg returns true if the endpoint requires bpf_lxc with section
// "to-container" to be attached at egress on the host facing veth pair
func (ep *epInfoCache) RequireEgressProg() bool {
	return ep.requireEgressProg
}

// RequireRouting returns true if the endpoint requires BPF routing to be
// enabled, when disabled, routing is delegated to Linux routing
func (ep *epInfoCache) RequireRouting() bool {
	return ep.requireRouting
}

// RequireEndpointRoute returns if the endpoint wants a per endpoint route
func (ep *epInfoCache) RequireEndpointRoute() bool {
	return ep.requireEndpointRoute
}

func (ep *epInfoCache) GetPolicyVerdictLogFilter() uint32 {
	return ep.policyVerdictLogFilter
}

func (ep *epInfoCache) IsHost() bool {
	return ep.endpoint.IsHost()
}
