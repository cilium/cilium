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
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
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

	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr:       ipIDPair.IP,
		logfields.Identity:     ipIDPair.ID,
		logfields.Modification: modType,
	})
	// Look up the current resources for the specified Identity.
	msg, err := cache.Lookup(NetworkPolicyHostsTypeURL, ipIDPair.ID.StringID())
	if err != nil {
		scopedLog.WithError(err).Warning("Can't lookup NPHDS cache")
		return
	}

	isHost := ipIDPair.Mask == nil
	switch modType {
	case ipcache.Upsert:
		var npHost *envoyAPI.NetworkPolicyHosts
		if msg == nil {
			npHost = &envoyAPI.NetworkPolicyHosts{Policy: uint64(ipIDPair.ID), HostAddresses: make([]string, 0, 1)}
		} else {
			npHost = msg.(*envoyAPI.NetworkPolicyHosts)
		}
		npHost.HostAddresses = append(npHost.HostAddresses, ipIDPair.PrefixString(isHost))
		sort.Strings(npHost.HostAddresses)
		if err := npHost.Validate(); err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				logfields.XDSResource: npHost,
			}).Warning("Could not validate NPHDS resource update on upsert")
			return
		}
		cache.Upsert(NetworkPolicyHostsTypeURL, ipIDPair.ID.StringID(), npHost, false)
	case ipcache.Delete:
		if msg == nil {
			// Doesn't exist; already deleted.
			return
		}
		cache.handleIPDelete(msg.(*envoyAPI.NetworkPolicyHosts), ipIDPair.ID.StringID(), ipIDPair.PrefixString(isHost))
	}
}

// handleIPUpsert deletes elements from the NPHDS cache with the specified peer IP->ID mapping.
func (cache *NPHDSCache) handleIPDelete(npHost *envoyAPI.NetworkPolicyHosts, peerIdentity, peerIP string) {
	targetIndex := -1

	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr:       peerIP,
		logfields.Identity:     peerIdentity,
		logfields.Modification: ipcache.Delete,
	})
	for i, endpointIP := range npHost.HostAddresses {
		if endpointIP == peerIP {
			targetIndex = i
			break
		}
	}
	if targetIndex < 0 {
		scopedLog.Fatal("Can't find IP in NPHDS cache")
		return
	}

	// If removing this host would result in empty list, delete it.
	// Otherwise, update to a list that doesn't contain the target IP
	if len(npHost.HostAddresses) <= 1 {
		cache.Delete(NetworkPolicyHostsTypeURL, peerIdentity, false)
	} else {
		if len(npHost.HostAddresses) == targetIndex {
			npHost.HostAddresses = npHost.HostAddresses[0:targetIndex]
		} else {
			npHost.HostAddresses = append(npHost.HostAddresses[0:targetIndex], npHost.HostAddresses[targetIndex+1:]...)
		}
		if err := npHost.Validate(); err != nil {
			scopedLog.WithError(err).Warning("Could not validate NPHDS resource update on delete")
			return
		}
		cache.Upsert(NetworkPolicyHostsTypeURL, peerIdentity, npHost, false)
	}
}
