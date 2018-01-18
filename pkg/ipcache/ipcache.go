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

package ipcache

import (
	"encoding/json"
	"path"
	"sort"
	"sync"

	"github.com/cilium/cilium/pkg/envoy"
	envoyAPI "github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultAddressSpace is the address space used if none is provided.
	// TODO - once pkg/node adds this to clusterConfiguration, remove.
	DefaultAddressSpace = "default"
)

var (
	// IPIdentitiesPath is the path to where endpoint IPs are stored in the key-value
	//store.
	IPIdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "ip", "v1")

	// IPIdentityCache caches the mapping of endpoint IPs to their corresponding
	// security identities across the entire cluster in which this instance of
	// Cilium is running.
	IPIdentityCache = NewIPCache()

	// AddressSpace is the address space (cluster, etc.) in which policy is
	// computed. It is determined by the orchestration system / runtime.
	AddressSpace = DefaultAddressSpace

	setupIPIdentityWatcher sync.Once
)

// IPCache is a caching of endpoint IP to security identity (and vice-versa) for
// all endpoints which are part of the same cluster.
type IPCache struct {
	mutex             lock.RWMutex
	ipToIdentityCache map[string]identity.NumericIdentity
	identityToIPCache map[identity.NumericIdentity]map[string]struct{}
}

// NewIPCache returns a new IPCache with the mappings of endpoint IP to security
// identity (and vice-versa) initialized.
func NewIPCache() *IPCache {
	return &IPCache{
		ipToIdentityCache: map[string]identity.NumericIdentity{},
		identityToIPCache: map[identity.NumericIdentity]map[string]struct{}{},
	}
}

// upsert adds / updates the provided IP and identity into both caches contained
// within ipc.
func (ipc *IPCache) upsert(endpointIP string, identity identity.NumericIdentity) {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()

	// An update is treated as a deletion and then an insert.
	ipc.deleteLocked(endpointIP)

	// Update both maps.
	ipc.ipToIdentityCache[endpointIP] = identity

	_, found := ipc.identityToIPCache[identity]
	if !found {
		ipc.identityToIPCache[identity] = map[string]struct{}{}
	}
	ipc.identityToIPCache[identity][endpointIP] = struct{}{}
}

// deleteLocked removes removes the provided IP-to-security-identity mapping
// from both caches within ipc with the assumption that ipc's mutex is held.
func (ipc *IPCache) deleteLocked(endpointIP string) {

	identity, found := ipc.ipToIdentityCache[endpointIP]
	if found {
		delete(ipc.ipToIdentityCache, endpointIP)
		delete(ipc.identityToIPCache[identity], endpointIP)
		if len(ipc.identityToIPCache[identity]) == 0 {
			delete(ipc.identityToIPCache, identity)
		}
	}
}

// delete removes the provided IP-to-security-identity mapping from both caches
// within ipc.
func (ipc *IPCache) delete(endpointIP string) {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	ipc.deleteLocked(endpointIP)
}

// LookupByIP returns the corresponding security identity that endpoint IP maps
// to within the provided IPCache, as well as if the corresponding entry exists
// in the IPCache.
func (ipc *IPCache) LookupByIP(endpointIP string) (identity.NumericIdentity, bool) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	identity, exists := ipc.ipToIdentityCache[endpointIP]
	return identity, exists
}

// LookupByIdentity returns the set of endpoint IPs that have security identity
// ID, as well as if the corresponding entry exists in the IPCache.
func (ipc *IPCache) LookupByIdentity(id identity.NumericIdentity) (map[string]struct{}, bool) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	ips, exists := ipc.identityToIPCache[id]
	return ips, exists
}

// IPIdentityMappingOwner is the interface the owner of an identity allocator
// must implement
type IPIdentityMappingOwner interface {
	// OnIPIdentityCacheChange will be called whenever there the state of the
	// IPCache has changed.
	OnIPIdentityCacheChange()
}

// GetIPIdentityMapModel returns all known endpoint IP to security identity mappings
// stored in the key-value store.
func GetIPIdentityMapModel() {
	// TODO (ianvernon) return model of ip to identity mapping. For use in CLI.
	// see GH-2555
}

func ipIdentityWatcher(owner IPIdentityMappingOwner) {

	for {
		watcher := kvstore.ListAndWatch("endpointIPWatcher", IPIdentitiesPath, 512)

		// Get events from channel as they come in.
		for event := range watcher.Events {

			var (
				cacheChanged bool
				ipIDPair     identity.IPIdentityPair
			)

			err := json.Unmarshal(event.Value, &ipIDPair)
			if err != nil {
				log.WithFields(logrus.Fields{"value": event.Value}).WithError(err).Errorf("not adding entry to ip cache; error unmarshaling data from key-value store")
				continue
			}

			// Synchronize local caching of endpoint IP to ipIDPair mapping with
			// operation key-value store has informed us about.

			ipStr := ipIDPair.IP.String()

			cachedIdentity, exists := IPIdentityCache.LookupByIP(ipStr)

			switch event.Typ {
			case kvstore.EventTypeCreate, kvstore.EventTypeModify:
				if !exists || cachedIdentity != ipIDPair.ID {
					IPIdentityCache.upsert(ipStr, ipIDPair.ID)
					cacheChanged = true

					endpointIPs, _ := IPIdentityCache.LookupByIdentity(ipIDPair.ID)

					// Update XDS Cache as well.
					ipStrings := make([]string, 0, len(endpointIPs))
					for endpointIP := range endpointIPs {
						ipStrings = append(ipStrings, endpointIP)
					}
					sort.Strings(ipStrings)
					envoy.NetworkPolicyHostsCache.Upsert(envoy.NetworkPolicyHostsTypeURL, ipIDPair.ID.StringID(), &envoyAPI.NetworkPolicyHosts{Policy: uint64(ipIDPair.ID), HostAddresses: ipStrings}, false)
				}
			case kvstore.EventTypeDelete:
				if exists {
					IPIdentityCache.delete(ipStr)
					cacheChanged = true

					endpointIPs, exists := IPIdentityCache.LookupByIdentity(ipIDPair.ID)
					if !exists {
						// Delete from XDS Cache as well.
						envoy.NetworkPolicyHostsCache.Delete(envoy.NetworkPolicyHostsTypeURL, cachedIdentity.StringID(), false)
					} else {

						// TODO (factor this out into a helper function).
						ipStrings := make([]string, 0, len(endpointIPs))
						for endpointIP := range endpointIPs {
							ipStrings = append(ipStrings, endpointIP)
						}
						sort.Strings(ipStrings)
						envoy.NetworkPolicyHostsCache.Upsert(envoy.NetworkPolicyHostsTypeURL, ipIDPair.ID.StringID(), &envoyAPI.NetworkPolicyHosts{Policy: uint64(ipIDPair.ID), HostAddresses: ipStrings}, false)
					}
				}
			}

			if cacheChanged {
				log.WithFields(logrus.Fields{
					"endpoint-ip":      ipIDPair.IP,
					"cached-identity":  cachedIdentity,
					logfields.Identity: ipIDPair.ID,
				}).Debugf("endpoint IP cache changed state")
				owner.OnIPIdentityCacheChange()
			}
		}

		log.Debugf("%s closed, restarting watch", watcher.String())
	}
}

// InitIPIdentityWatcher initializes the watcher for ip-identity mapping events
// in the key-value store.
func InitIPIdentityWatcher(owner IPIdentityMappingOwner) {
	setupIPIdentityWatcher.Do(func() {
		go ipIdentityWatcher(owner)
	})
}
