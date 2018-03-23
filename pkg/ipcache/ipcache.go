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
	"fmt"
	"net"
	"path"
	"sort"
	"strings"
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

// Lock locks the IPCache's mutex.
func (ipc *IPCache) Lock() {
	ipc.mutex.Lock()
}

// Unlock unlocks the IPCache's mutex.
func (ipc *IPCache) Unlock() {
	ipc.mutex.Unlock()
}

// RLock RLocks the IPCache's mutex.
func (ipc *IPCache) RLock() {
	ipc.mutex.RLock()
}

// RUnlock RUnlocks the IPCache's mutex.
func (ipc *IPCache) RUnlock() {
	ipc.mutex.RUnlock()
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

// LookupByIPRLocked returns the corresponding security identity that endpoint IP maps
// to within the provided IPCache, as well as if the corresponding entry exists
// in the IPCache.
func (ipc *IPCache) LookupByIPRLocked(endpointIP string) (identity.NumericIdentity, bool) {

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
	OnIPIdentityCacheChange(modType CacheModification, ipIDPair identity.IPIdentityPair)

	// OnIPIdentityCacheGC will be called to sync other components which are
	// reliant upon the IPIdentityCache with the IPIdentityCache.
	OnIPIdentityCacheGC()
}

// GetIPIdentityMapModel returns all known endpoint IP to security identity mappings
// stored in the key-value store.
func GetIPIdentityMapModel() {
	// TODO (ianvernon) return model of ip to identity mapping. For use in CLI.
	// see GH-2555
}

// CacheModification represents the type of operation performed upon IPCache.
type CacheModification string

const (
	// Upsert represents Upsertion into IPCache.
	Upsert CacheModification = "Upsert"

	// Delete represents deletion of an entry in IPCache.
	Delete CacheModification = "Delete"
)

func keyToIP(key string) (net.IP, error) {
	requiredPrefix := fmt.Sprintf("%s/", path.Join(IPIdentitiesPath, AddressSpace))
	if !strings.HasPrefix(key, requiredPrefix) {
		return nil, fmt.Errorf("Found invalid key %s outside of prefix %s", key, IPIdentitiesPath)
	}

	suffix := strings.TrimPrefix(key, requiredPrefix)

	parsedIP := net.ParseIP(suffix)
	if parsedIP == nil {
		return nil, fmt.Errorf("unable to parse IP from suffix %s", suffix)
	}

	return parsedIP, nil
}

func ipIdentityWatcher(owner IPIdentityMappingOwner) {

	for {

		watcher := kvstore.ListAndWatch("endpointIPWatcher", IPIdentitiesPath, 512)

		// Get events from channel as they come in.
		for event := range watcher.Events {

			scopedLog := log.WithFields(logrus.Fields{"kvstore-event": event.Typ.String(), "key": event.Key})
			scopedLog.Debug("received event")

			var (
				cacheChanged      bool
				cacheModification CacheModification
				ipIDPair          identity.IPIdentityPair
				cachedIdentity    identity.NumericIdentity
			)

			// Key and value are empty for ListDone event types; do not try
			// to unmarshal key or value.
			if event.Typ == kvstore.EventTypeListDone {
				owner.OnIPIdentityCacheGC()
				continue
			}

			switch event.Typ {
			case kvstore.EventTypeCreate, kvstore.EventTypeModify:

				err := json.Unmarshal(event.Value, &ipIDPair)
				if err != nil {
					scopedLog.WithError(err).Errorf("not adding entry to ip cache; error unmarshaling data from key-value store")
					continue
				}

				ipStr := ipIDPair.IP.String()

				cachedIdentity, exists := IPIdentityCache.LookupByIP(ipStr)

				if !exists || cachedIdentity != ipIDPair.ID {
					IPIdentityCache.upsert(ipStr, ipIDPair.ID)
					cacheChanged = true
					cacheModification = Upsert

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
				// Synchronize local caching of endpoint IP to ipIDPair mapping with
				// operation key-value store has informed us about.

				convertedKey, err := keyToIP(event.Key)

				// Value is not present in deletion event; need to convert key
				// to IP.
				if err != nil {
					scopedLog.Error("error parsing IP from key: %s", err)
					continue
				}

				ipIDPair.IP = convertedKey
				ipStr := convertedKey.String()

				cachedIdentity, exists := IPIdentityCache.LookupByIP(ipStr)

				if exists {

					// Perform lookup first to get list of identities.
					identityToDelete, _ := IPIdentityCache.LookupByIP(ipStr)
					ipIDPair.ID = identityToDelete

					endpointIPs, exists := IPIdentityCache.LookupByIdentity(identityToDelete)

					IPIdentityCache.delete(ipStr)
					cacheChanged = true
					cacheModification = Delete

					if !exists {
						// Delete from XDS Cache as well.
						envoy.NetworkPolicyHostsCache.Delete(envoy.NetworkPolicyHostsTypeURL, cachedIdentity.StringID(), false)
					} else {
						// Update list in XDS cache without this ip.

						// TODO (factor this out into a helper function).
						ipStrings := make([]string, 0, len(endpointIPs))
						for endpointIP := range endpointIPs {
							ipStrings = append(ipStrings, endpointIP)
						}
						sort.Strings(ipStrings)
						envoy.NetworkPolicyHostsCache.Upsert(envoy.NetworkPolicyHostsTypeURL, identityToDelete.StringID(), &envoyAPI.NetworkPolicyHosts{Policy: uint64(identityToDelete), HostAddresses: ipStrings}, false)
					}
				}
			}

			if cacheChanged {
				log.WithFields(logrus.Fields{
					"endpoint-ip":      ipIDPair.IP,
					"cached-identity":  cachedIdentity,
					logfields.Identity: ipIDPair.ID,
				}).Debugf("endpoint IP cache %s", cacheModification)

				// Callback upon cache updates.
				owner.OnIPIdentityCacheChange(cacheModification, ipIDPair)
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
