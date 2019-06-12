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

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

// EpInfoCache describes the set of lxcmap entries necessary to describe an Endpoint
// in the BPF maps. It is generated while holding the Endpoint lock, then used
// after releasing that lock to push the entries into the datapath.
// Functions below implement the EndpointFrontend interface with this cached information.
type EpInfoCache struct {
	// revision is used by the endpoint regeneration code to determine
	// whether this cache is out-of-date wrt the underlying endpoint.
	revision uint64

	// For lxcmap.EndpointFrontend
	keys  []*lxcmap.EndpointKey
	value *lxcmap.EndpointInfo

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
	cidr4PrefixLengths, cidr6PrefixLengths []int
	options                                *option.IntOptions

	// endpoint is used to get the endpoint's logger.
	//
	// Do NOT use this for fetching endpoint data directly; this structure
	// is intended as a safe cache of endpoint data that is assembled while
	// holding the endpoint lock, for use beyond the holding of that lock.
	// Dereferencing fields in this endpoint is not guaranteed to be safe.
	endpoint *Endpoint
}

// Must be called when endpoint is still locked.
func (e *Endpoint) createEpInfoCache(epdir string) *EpInfoCache {
	cidr6, cidr4 := e.GetCIDRPrefixLengths()

	ep := &EpInfoCache{
		revision: e.nextPolicyRevision,
		keys:     e.GetBPFKeys(),

		epdir:  epdir,
		id:     e.GetID(),
		ifName: e.IfName,
		ipvlan: e.HasIpvlanDataPath(),

		identity:              e.GetIdentity(),
		mac:                   e.GetNodeMAC(),
		ipv4:                  e.IPv4Address(),
		ipv6:                  e.IPv6Address(),
		conntrackLocal:        e.ConntrackLocalLocked(),
		requireARPPassthrough: e.RequireARPPassthrough(),
		requireEgressProg:     e.RequireEgressProg(),
		requireRouting:        e.RequireRouting(),
		requireEndpointRoute:  e.RequireEndpointRoute(),
		cidr4PrefixLengths:    cidr4,
		cidr6PrefixLengths:    cidr6,
		options:               e.Options.DeepCopy(),

		endpoint: e,
	}

	var err error
	ep.value, err = e.GetBPFValue()
	if err != nil {
		log.WithField(logfields.EndpointID, e.ID).WithError(err).Error("getBPFValue failed")
		return nil
	}
	return ep
}

// InterfaceName returns the name of the link-layer interface used for
// communicating with the endpoint.
func (ep *EpInfoCache) InterfaceName() string {
	return ep.ifName
}

// MapPath returns tail call map path
func (ep *EpInfoCache) MapPath() string {
	return ep.endpoint.BPFIpvlanMapPath()
}

// GetID returns the endpoint's ID.
func (ep *EpInfoCache) GetID() uint64 {
	return ep.id
}

// StringID returns the endpoint's ID in a string.
func (ep *EpInfoCache) StringID() string {
	return fmt.Sprintf("%d", ep.id)
}

// GetIdentity returns the security identity of the endpoint.
func (ep *EpInfoCache) GetIdentity() identity.NumericIdentity {
	return ep.identity
}

// Logger returns the logger for the endpoint that is being cached.
func (ep *EpInfoCache) Logger(subsystem string) *logrus.Entry {
	return ep.endpoint.Logger(subsystem)
}

// HasIpvlanDataPath returns whether the endpoint's datapath is implemented via ipvlan.
func (ep *EpInfoCache) HasIpvlanDataPath() bool {
	return ep.ipvlan
}

// IPv4Address returns the cached IPv4 address for the endpoint.
func (ep *EpInfoCache) IPv4Address() addressing.CiliumIPv4 {
	return ep.ipv4
}

// IPv6Address returns the cached IPv6 address for the endpoint.
func (ep *EpInfoCache) IPv6Address() addressing.CiliumIPv6 {
	return ep.ipv6
}

// StateDir returns the directory for the endpoint's (next) state.
func (ep *EpInfoCache) StateDir() string    { return ep.epdir }
func (ep *EpInfoCache) GetNodeMAC() mac.MAC { return ep.mac }

// GetBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map
func (ep *EpInfoCache) GetBPFKeys() []*lxcmap.EndpointKey {
	return ep.keys
}

// GetBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
// Must only be called if init() succeeded.
func (ep *EpInfoCache) GetBPFValue() (*lxcmap.EndpointInfo, error) {
	return ep.value, nil
}

func (ep *EpInfoCache) ConntrackLocalLocked() bool {
	return ep.conntrackLocal
}

func (ep *EpInfoCache) GetCIDRPrefixLengths() ([]int, []int) {
	return ep.cidr6PrefixLengths, ep.cidr4PrefixLengths
}

func (ep *EpInfoCache) GetOptions() *option.IntOptions {
	return ep.options
}

// RequireARPPassthrough returns true if the datapath must implement ARP
// passthrough for this endpoint
func (ep *EpInfoCache) RequireARPPassthrough() bool {
	return ep.requireARPPassthrough
}

// RequireEgressProg returns true if the endpoint requires bpf_lxc with esction
// "to-container" to be attached at egress on the host facing veth pair
func (ep *EpInfoCache) RequireEgressProg() bool {
	return ep.requireEgressProg
}

// RequireRouting returns true if the endpoint requires BPF routing to be
// enabled, when disabled, routing is delegated to Linux routing
func (ep *EpInfoCache) RequireRouting() bool {
	return ep.requireRouting
}

// RequireEndpointRoute returns if the endpoint wants a per endpoint route
func (ep *EpInfoCache) RequireEndpointRoute() bool {
	return ep.requireEndpointRoute
}
