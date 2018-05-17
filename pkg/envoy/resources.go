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
	modType ipcache.CacheModification, newIPIDPair identity.IPIdentityPair) {

	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr:       newIPIDPair.IP,
		logfields.Identity:     newIPIDPair.ID,
		logfields.Modification: modType,
	})
	// Look up the current resources for the specified Identity.
	resourceName := newIPIDPair.ID.StringID()
	msg, err := cache.Lookup(NetworkPolicyHostsTypeURL, resourceName)
	if err != nil {
		scopedLog.WithError(err).Warning("Can't lookup NPHDS cache")
		return
	}

	switch modType {
	case ipcache.Upsert:
		var hostAddresses []string
		if msg == nil {
			hostAddresses = make([]string, 0, 1)
		} else {
			// If the resource already exists, create a copy of it and insert
			// the new IP address into its HostAddresses list.
			npHost := msg.(*envoyAPI.NetworkPolicyHosts)
			hostAddresses = make([]string, 0, len(npHost.HostAddresses)+1)
			hostAddresses = append(hostAddresses, npHost.HostAddresses...)
		}
		hostAddresses = append(hostAddresses, newIPIDPair.PrefixString())
		sort.Strings(hostAddresses)

		newNpHost := envoyAPI.NetworkPolicyHosts{
			Policy:        uint64(newIPIDPair.ID),
			HostAddresses: hostAddresses,
		}
		if err := newNpHost.Validate(); err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				logfields.XDSResource: newNpHost,
			}).Warning("Could not validate NPHDS resource update on upsert")
			return
		}
		cache.Upsert(NetworkPolicyHostsTypeURL, resourceName, &newNpHost, false)
	case ipcache.Delete:
		if msg == nil {
			// Doesn't exist; already deleted.
			return
		}
		cache.handleIPDelete(msg.(*envoyAPI.NetworkPolicyHosts), resourceName, newIPIDPair.PrefixString())
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
		// If the resource is to be updated, create a copy of it before
		// removing the IP address from its HostAddresses list.
		hostAddresses := make([]string, 0, len(npHost.HostAddresses)-1)
		if len(npHost.HostAddresses) == targetIndex {
			hostAddresses = append(hostAddresses, npHost.HostAddresses[0:targetIndex]...)
		} else {
			hostAddresses = append(hostAddresses, npHost.HostAddresses[0:targetIndex]...)
			hostAddresses = append(hostAddresses, npHost.HostAddresses[targetIndex+1:]...)
		}

		newNpHost := envoyAPI.NetworkPolicyHosts{
			Policy:        uint64(npHost.Policy),
			HostAddresses: hostAddresses,
		}
		if err := newNpHost.Validate(); err != nil {
			scopedLog.WithError(err).Warning("Could not validate NPHDS resource update on delete")
			return
		}
		cache.Upsert(NetworkPolicyHostsTypeURL, peerIdentity, &newNpHost, false)
	}
}
