// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"net/netip"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
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

	// For datapath.EndpointConfiguration
	identity               identity.NumericIdentity
	mac                    mac.MAC
	ipv4                   netip.Addr
	ipv6                   netip.Addr
	conntrackLocal         bool
	requireARPPassthrough  bool
	requireEgressProg      bool
	requireRouting         bool
	requireEndpointRoute   bool
	policyVerdictLogFilter uint32
	options                *option.IntOptions
	lxcMAC                 mac.MAC
	ifIndex                int
	netNsCookie            uint64

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
	ep := &epInfoCache{
		revision: e.nextPolicyRevision,

		epdir:                  epdir,
		id:                     e.GetID(),
		ifName:                 e.ifName,
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
		options:                e.Options.DeepCopy(),
		lxcMAC:                 e.mac,
		ifIndex:                e.ifIndex,
		netNsCookie:            e.NetNsCookie,

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

// GetID returns the endpoint's ID.
func (ep *epInfoCache) GetID() uint64 {
	return ep.id
}

// StringID returns the endpoint's ID in a string.
func (ep *epInfoCache) StringID() string {
	return strconv.FormatUint(ep.id, 10)
}

// GetIdentity returns the security identity of the endpoint.
func (ep *epInfoCache) GetIdentity() identity.NumericIdentity {
	return ep.identity
}

// GetIdentityLocked returns the security identity of the endpoint.
func (ep *epInfoCache) GetIdentityLocked() identity.NumericIdentity {
	return ep.identity
}

// GetEndpointNetNsCookie returns the network namespace cookie for the endpoint
func (ep *epInfoCache) GetEndpointNetNsCookie() uint64 {
	return ep.netNsCookie
}

// Logger returns the logger for the endpoint that is being cached.
func (ep *epInfoCache) Logger(subsystem string) *logrus.Entry {
	return ep.endpoint.Logger(subsystem)
}

// IPv4Address returns the cached IPv4 address for the endpoint.
func (ep *epInfoCache) IPv4Address() netip.Addr {
	return ep.ipv4
}

// IPv6Address returns the cached IPv6 address for the endpoint.
func (ep *epInfoCache) IPv6Address() netip.Addr {
	return ep.ipv6
}

// StateDir returns the directory for the endpoint's (next) state.
func (ep *epInfoCache) StateDir() string    { return ep.epdir }
func (ep *epInfoCache) GetNodeMAC() mac.MAC { return ep.mac }

func (ep *epInfoCache) ConntrackLocalLocked() bool {
	return ep.conntrackLocal
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
