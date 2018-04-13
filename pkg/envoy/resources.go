// Copyright 2018 Authors of Cilium
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

package envoy

import (
	"sort"

	envoyAPI "github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
)

const (
	// ListenerTypeURL is the type URL of Listener resources.
	ListenerTypeURL = "type.googleapis.com/envoy.api.v2.Listener"

	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL = "type.googleapis.com/cilium.NetworkPolicy"

	// NetworkPolicyHostsTypeURL is the type URL of NetworkPolicyHosts resources.
	NetworkPolicyHostsTypeURL = "type.googleapis.com/cilium.NetworkPolicyHosts"
)

// NPHDSCache is a cache of resources in the Network Policy Hosts Discovery
// Service.
type NPHDSCache struct {
	*xds.Cache
}

func newNPHDSCache() NPHDSCache {
	return NPHDSCache{Cache: xds.NewCache()}
}

var (
	// NetworkPolicyHostsCache is the global cache of resources of type
	// NetworkPolicyHosts. Resources in this cache must have the
	// NetworkPolicyHostsTypeURL type URL.
	NetworkPolicyHostsCache = newNPHDSCache()
)

// OnIPIdentityCacheGC is required to implement IPIdentityMappingListener.
func (cache *NPHDSCache) OnIPIdentityCacheGC() {
	// We don't have anything to synchronize in this case.
}

// OnIPIdentityCacheChange pushes modifications to the IP<->Identity mapping
// into the Network Policy Host Discovery Service (NPHDS).
func (cache *NPHDSCache) OnIPIdentityCacheChange(
	modType ipcache.CacheModification, ipIDPair identity.IPIdentityPair) {

	endpointIPs, isIdentityInCache := ipcache.IPIdentityCache.LookupByIdentity(ipIDPair.ID)
	if modType == ipcache.Delete && !isIdentityInCache {
		cache.Delete(NetworkPolicyHostsTypeURL, ipIDPair.ID.StringID(), false)
	} else {
		ipStrings := make([]string, 0, len(endpointIPs))
		for endpointIP := range endpointIPs {
			ipStrings = append(ipStrings, endpointIP)
		}
		sort.Strings(ipStrings)
		npHost := &envoyAPI.NetworkPolicyHosts{Policy: uint64(ipIDPair.ID), HostAddresses: ipStrings}
		cache.Upsert(NetworkPolicyHostsTypeURL, ipIDPair.ID.StringID(), npHost, false)
	}
}
