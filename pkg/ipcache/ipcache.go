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
	"strings"
	"sync"

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

// UpsertIPToKVStore updates / inserts the provided IP->Identity mapping into the
// kvstore, which will subsequently trigger an event in ipIdentityWatcher().
func UpsertIPToKVStore(IP net.IP, ID identity.NumericIdentity, metadata string) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, IP.String())
	ipIDPair := identity.IPIdentityPair{
		IP:       IP,
		ID:       ID,
		Metadata: metadata,
	}

	marshaledIPIDPair, err := json.Marshal(ipIDPair)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.IPAddr:       ipIDPair.IP,
		logfields.Identity:     ipIDPair.ID,
		logfields.Modification: Upsert,
	}).Debug("upserting IP->ID mapping to kvstore")

	return kvstore.Update(ipKey, marshaledIPIDPair, true)
}

// DeleteIPFromKVStore removes the IP->Identity mapping for the specified ip from the
// kvstore, which will subsequently trigger an event in ipIdentityWatcher().
func DeleteIPFromKVStore(ip string) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, ip)
	return kvstore.Delete(ipKey)
}

// Upsert adds / updates the provided IP<->identity mapping into the IPCache.
func (ipc *IPCache) Upsert(IP string, identity identity.NumericIdentity) {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()

	// An update is treated as a deletion and then an insert.
	ipc.deleteLocked(IP)

	log.WithFields(logrus.Fields{
		logfields.IPAddr:   IP,
		logfields.Identity: identity,
	}).Debug("Upserting into ipcache layer")

	// Update both maps.
	ipc.ipToIdentityCache[IP] = identity

	_, found := ipc.identityToIPCache[identity]
	if !found {
		ipc.identityToIPCache[identity] = map[string]struct{}{}
	}
	ipc.identityToIPCache[identity][IP] = struct{}{}
}

// deleteLocked removes removes the provided IP-to-security-identity mapping
// from ipc with the assumption that the IPCache's mutex is held.
func (ipc *IPCache) deleteLocked(IP string) {
	log.WithFields(logrus.Fields{
		logfields.IPAddr: IP,
	}).Debug("Removing from ipcache layer")

	identity, found := ipc.ipToIdentityCache[IP]
	if found {
		delete(ipc.ipToIdentityCache, IP)
		delete(ipc.identityToIPCache[identity], IP)
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
	return ipc.LookupByIPRLocked(endpointIP)
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

// IPIdentityMappingListener represents a component that is interested in
// learning about IP to Identity mapping events.
type IPIdentityMappingListener interface {
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

func ipIdentityWatcher(listeners []IPIdentityMappingListener) {
	log.Info("Starting IP identity watcher")

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
				ipIsInCache       bool
			)

			switch event.Typ {
			case kvstore.EventTypeListDone:
				for _, listener := range listeners {
					listener.OnIPIdentityCacheGC()
				}
			case kvstore.EventTypeCreate, kvstore.EventTypeModify:

				err := json.Unmarshal(event.Value, &ipIDPair)
				if err != nil {
					scopedLog.WithError(err).Errorf("not adding entry to ip cache; error unmarshaling data from key-value store")
					continue
				}

				ipStr := ipIDPair.IP.String()

				cachedIdentity, ipIsInCache = IPIdentityCache.LookupByIP(ipStr)

				// Need to add or update entry.
				if !ipIsInCache || cachedIdentity != ipIDPair.ID {
					IPIdentityCache.Upsert(ipStr, ipIDPair.ID)
					cacheChanged = true
					cacheModification = Upsert
				}
			case kvstore.EventTypeDelete:
				// Synchronize local caching of endpoint IP to ipIDPair mapping with
				// operation key-value store has informed us about.

				keyIP, err := keyToIP(event.Key)

				// Value is not present in deletion event; need to convert key
				// to IP.
				if err != nil {
					scopedLog.Error("error parsing IP from key: %s", err)
					continue
				}

				ipIDPair.IP = keyIP
				ipStr := keyIP.String()

				cachedIdentity, ipIsInCache = IPIdentityCache.LookupByIP(ipStr)

				if ipIsInCache {
					// Set value of ipIDPair.ID for logging purposes and owner callback.
					ipIDPair.ID = cachedIdentity

					IPIdentityCache.delete(ipStr)
					cacheChanged = true
					cacheModification = Delete
				}
			}

			if cacheChanged {
				log.WithFields(logrus.Fields{
					"endpoint-ip":          ipIDPair.IP,
					"cached-identity":      cachedIdentity,
					logfields.Identity:     ipIDPair.ID,
					logfields.Modification: cacheModification,
				}).Debugf("endpoint IP cache state change")

				// Callback upon cache updates.
				for _, listener := range listeners {
					// In the case the mapping for an IP is updated (vs.
					// inserted), first delete the mapping to the old ID.
					if ipIsInCache && cacheModification == Upsert {
						cachedPair := ipIDPair
						cachedPair.ID = cachedIdentity
						listener.OnIPIdentityCacheChange(Delete, cachedPair)
					}
					listener.OnIPIdentityCacheChange(cacheModification, ipIDPair)
				}
			}
		}

		log.Debugf("%s closed, restarting watch", watcher.String())
	}
}

// InitIPIdentityWatcher initializes the watcher for ip-identity mapping events
// in the key-value store.
func InitIPIdentityWatcher(listeners []IPIdentityMappingListener) {
	setupIPIdentityWatcher.Do(func() {
		go ipIdentityWatcher(listeners)
	})
}
