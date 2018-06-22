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

	// AddressSpace is the address space (cluster, etc.) in which policy is
	// computed. It is determined by the orchestration system / runtime.
	AddressSpace = DefaultAddressSpace

	// globalMap wraps the kvstore and provides reference-tracking for keys
	// that are upserted or released from the kvstore.
	globalMap *kvReferenceCounter

	setupIPIdentityWatcher sync.Once
)

// store is a key-value store for an underlying implementation, provided to
// mock out the kvstore for unit testing.
type store interface {
	// update will insert the {key, value} tuple into the underlying
	// kvstore.
	upsert(key string, value []byte, lease bool) error

	// delete will remove the key from the underlying kvstore.
	release(key string) error
}

// kvstoreImplementation is provided to mock out the kvstore for unit testing.
type kvstoreImplementation struct{}

// upsert places the mapping of {key, value} into the kvstore, optionally with
// a lease.
func (k kvstoreImplementation) upsert(key string, value []byte, lease bool) error {
	return kvstore.Update(key, value, lease)
}

// release removes the specified key from the kvstore.
func (k kvstoreImplementation) release(key string) error {
	return kvstore.Delete(key)
}

// kvReferenceCounter provides a thin wrapper around the kvstore which adds
// reference tracking for all entries being updated. When the first key is
// updated, it adds a reference to the kvstore and tracks the reference
// internally. Subsequent updates also update the kvstore, and add a referenc.
// Deletes from the referenceCounter are only propagated to the kvstore when
// the final reference is released.
//
// This has some small overlap with the pkg/kvstore/allocator but this is only
// a map from key to reference count rather than also tracking values.
type kvReferenceCounter struct {
	lock.Mutex
	store

	// keys is a map from key to reference count for locally-referenced
	// keys in the global kvstore.
	keys map[string]uint64
}

// newKVReferenceCounter creates a new reference counter using the global
// kvstore package as the underlying store.
func newKVReferenceCounter(s store) *kvReferenceCounter {
	return &kvReferenceCounter{
		store: s,
		keys:  map[string]uint64{},
	}
}

// upsert attempts to insert the specified {key, ipIDPair} into the kvstore. If
// the key has previously been upserted, increments a reference on the key.
// Always updates the underlying store with this {key, ipIDPair} tuple.
// Only adds a reference to the key if the upsert is successful.
func (r *kvReferenceCounter) upsert(ipKey string, ipIDPair identity.IPIdentityPair) error {
	marshaledIPIDPair, err := json.Marshal(ipIDPair)
	if err != nil {
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.IPAddr:       ipIDPair.IP,
		logfields.IPMask:       ipIDPair.Mask,
		logfields.Identity:     ipIDPair.ID,
		logfields.Modification: Upsert,
	}).Debug("upserting IP->ID mapping to kvstore")

	r.Lock()
	defer r.Unlock()
	refcnt := r.keys[ipKey] // 0 if not found
	refcnt++
	err = r.store.upsert(ipKey, marshaledIPIDPair, true)
	if err == nil {
		r.keys[ipKey] = refcnt
	}
	return err
}

// release removes a reference to the specified key. If the number of
// references reaches 0, the key is removed from the underlying kvstore.
func (r *kvReferenceCounter) release(key string) (err error) {
	r.Lock()
	defer r.Unlock()

	refcnt, ok := r.keys[key] // 0 if not found
	if ok {
		refcnt--
	}

	if refcnt == 0 {
		err = r.store.release(key)
		delete(r.keys, key)
	} else {
		r.keys[key] = refcnt
	}
	return err
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

	return globalMap.upsert(ipKey, ipIDPair)
}

// upsertIPNetToKVStore updates / inserts the provided CIDR->Identity mapping
// into the kvstore, which will subsequently trigger an event in
// ipIdentityWatcher().
func upsertIPNetToKVStore(prefix *net.IPNet, ID *identity.Identity) error {
	// Reserved identities are handled locally, don't push them to kvstore.
	if ID.IsReserved() {
		return nil
	}

	ipKey := path.Join(IPIdentitiesPath, AddressSpace, prefix.String())
	ipIDPair := identity.IPIdentityPair{
		IP:       prefix.IP,
		Mask:     prefix.Mask,
		ID:       ID.ID,
		Metadata: AddressSpace, // XXX: Should we associate more metadata?
	}

	return globalMap.upsert(ipKey, ipIDPair)
}

// keyToIPNet returns the IPNet describing the key, whether it is a host, and
// an error (if one occurs)
func keyToIPNet(key string) (parsedPrefix *net.IPNet, host bool, err error) {
	requiredPrefix := fmt.Sprintf("%s/", path.Join(IPIdentitiesPath, AddressSpace))
	if !strings.HasPrefix(key, requiredPrefix) {
		err = fmt.Errorf("Found invalid key %s outside of prefix %s", key, IPIdentitiesPath)
		return
	}

	suffix := strings.TrimPrefix(key, requiredPrefix)

	// Key is formatted as "prefix/192.0.2.0/24" for CIDRs
	_, parsedPrefix, err = net.ParseCIDR(suffix)
	if err != nil {
		// Key is likely a host in the format "prefix/192.0.2.3"
		parsedIP := net.ParseIP(suffix)
		if parsedIP == nil {
			err = fmt.Errorf("unable to parse IP from suffix %s", suffix)
			return
		}
		err = nil
		host = true
		ipv4 := parsedIP.To4()
		bits := net.IPv6len * 8
		if ipv4 != nil {
			parsedIP = ipv4
			bits = net.IPv4len * 8
		}
		parsedPrefix = &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(bits, bits)}
	}

	return
}

// upsertIPNetsToKVStore inserts a CIDR->Identity mapping into the kvstore
// ipcache for each of the specified prefixes and identities. That is to say,
// prefixes[0] is mapped to identities[0].
//
// If any Prefix->Identity mapping cannot be created, it will not create any
// of the mappings and returns an error.
//
// The caller should check the prefix lengths against the underlying IPCache
// implementation using CheckPrefixLengths prior to upserting to the kvstore.
func upsertIPNetsToKVStore(prefixes []*net.IPNet, identities []*identity.Identity) (err error) {
	if len(prefixes) != len(identities) {
		return fmt.Errorf("Invalid []Prefix->[]Identity ipcache mapping requested: prefixes=%d identities=%d", len(prefixes), len(identities))
	}
	for i, prefix := range prefixes {
		id := identities[i]
		err = upsertIPNetToKVStore(prefix, id)
		if err != nil {
			for j := 0; j < i; j++ {
				ipKey := path.Join(IPIdentitiesPath, AddressSpace, prefix.String())
				err2 := globalMap.release(ipKey)
				if err2 != nil {
					log.WithFields(logrus.Fields{
						"prefix": prefix.String(),
					}).Error("Failed to clean up CIDR->ID mappings")
				}
			}
		}
	}

	return
}

// DeleteIPFromKVStore removes the IP->Identity mapping for the specified ip
// from the kvstore, which will subsequently trigger an event in
// ipIdentityWatcher().
func DeleteIPFromKVStore(ip string) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, ip)
	return globalMap.release(ipKey)
}

// deleteIPNetsFromKVStore removes the Prefix->Identity mappings for the
// specified slice of prefixes from the kvstore, which will subsequently
// trigger an event in ipIdentityWatcher().
func deleteIPNetsFromKVStore(prefixes []*net.IPNet) (err error) {
	for _, prefix := range prefixes {
		ipKey := path.Join(IPIdentitiesPath, AddressSpace, prefix.String())
		if err2 := globalMap.release(ipKey); err2 != nil {
			err = err2
			log.WithFields(logrus.Fields{
				"prefix": prefix.String(),
			}).Error("Failed to delete CIDR->ID mappings")
		}
	}

	return
}

// findShadowedCIDR attempts to search for a CIDR with a full prefix (eg, /32
// for IPv4) which matches the IP in the specified pair. Only performs the
// search if the pair's IP represents a host IP.
// Returns the identity and whether the IP was found.
func findShadowedCIDR(pair *identity.IPIdentityPair) (identity.NumericIdentity, bool) {
	if !pair.IsHost() {
		return identity.InvalidIdentity, false
	}
	bits := net.IPv6len * 8
	if pair.IP.To4() != nil {
		bits = net.IPv4len * 8
	}
	cidrStr := fmt.Sprintf("%s/%d", pair.PrefixString(), bits)
	return IPIdentityCache.LookupByIP(cidrStr)
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

			// Synchronize local caching of endpoint IP to ipIDPair mapping with
			// operation key-value store has informed us about.
			//
			// To resolve conflicts between hosts and full CIDR prefixes:
			// - Insert hosts into the cache as ".../w.x.y.z"
			// - Insert CIDRS into the cache as ".../w.x.y.z/N"
			// - If a host entry created, notify the listeners.
			// - If a CIDR is created and there's no overlapping host
			//   entry, ie it is a less than fully masked CIDR, OR
			//   it is a fully masked CIDR and there is no corresponding
			//   host entry, then:
			//   - Notify the listeners.
			//   - Otherwise, do not notify listeners.
			// - If a host is removed, check for an overlapping CIDR
			//   and if it exists, notify the listeners with an upsert
			//   for the CIDR's identity
			// - If any other deletion case, notify listeners of
			//   the deletion event.
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

				ipStr := ipIDPair.PrefixString()
				cachedIdentity, ipIsInCache = IPIdentityCache.LookupByIP(ipStr)

				// Host IP identities take precedence over CIDR
				// identities, so if this event is for a full
				// CIDR prefix and there's an existing entry
				// with a different ID, then break out.
				if !ipIDPair.IsHost() {
					ones, bits := ipIDPair.Mask.Size()
					if ipIsInCache && ones == bits {
						if cachedIdentity != ipIDPair.ID {
							IPIdentityCache.Upsert(ipStr, ipIDPair.ID)
							scopedLog.WithField(logfields.IPAddr, ipIDPair.IP).
								Infof("Received KVstore update for CIDR overlapping with endpoint IP.")
						}
						continue
					}
				}

				// Insert or update the IP -> ID mapping.
				if !ipIsInCache || cachedIdentity != ipIDPair.ID {
					IPIdentityCache.Upsert(ipStr, ipIDPair.ID)
					cacheChanged = true
					cacheModification = Upsert
				}
			case kvstore.EventTypeDelete:
				// Value is not present in deletion event;
				// need to convert kvstore key to IP.
				ipnet, isHost, err := keyToIPNet(event.Key)
				if err != nil {
					scopedLog.Error("error parsing IP from key: %s", err)
					continue
				}

				ipIDPair.IP = ipnet.IP
				if isHost {
					ipIDPair.Mask = nil
				} else {
					ipIDPair.Mask = ipnet.Mask
				}
				ipStr := ipIDPair.PrefixString()
				cachedIdentity, ipIsInCache = IPIdentityCache.LookupByIP(ipStr)

				if ipIsInCache {
					cacheChanged = true
					IPIdentityCache.delete(ipStr)

					// Set up the IPIDPair and cacheModification for listener callbacks
					prefixIdentity, shadowedCIDR := findShadowedCIDR(&ipIDPair)
					if shadowedCIDR {
						scopedLog.WithField(logfields.IPAddr, ipIDPair.IP).
							Infof("Received KVstore deletion for endpoint IP shadowing CIDR, restoring CIDR.")
						ipIDPair.ID = prefixIdentity
						cacheModification = Upsert
					} else {
						ipIDPair.ID = cachedIdentity
						cacheModification = Delete
					}
				}
			}

			if cacheChanged {
				log.WithFields(logrus.Fields{
					logfields.IPAddr:       ipIDPair.IP,
					logfields.IPMask:       ipIDPair.Mask,
					logfields.OldIdentity:  cachedIdentity,
					logfields.Identity:     ipIDPair.ID,
					logfields.Modification: cacheModification,
				}).Debugf("endpoint IP cache state change")

				var oldIPIDPair *identity.IPIdentityPair
				if ipIsInCache && cacheModification == Upsert {
					// If an existing mapping is updated,
					// provide the existing mapping to the
					// listener so it can easily clean up
					// the old mapping.
					pair := ipIDPair
					pair.ID = cachedIdentity
					oldIPIDPair = &pair
				}
				// Callback upon cache updates.
				for _, listener := range listeners {
					listener.OnIPIdentityCacheChange(cacheModification, oldIPIDPair, ipIDPair)
				}
			}
		}

		log.Debugf("%s closed, restarting watch", watcher.String())
	}
}

// InitIPIdentityWatcher initializes the watcher for ip-identity mapping events
// in the key-value store.
func InitIPIdentityWatcher(listeners []IPIdentityMappingListener) {
	globalMap = newKVReferenceCounter(kvstoreImplementation{})
	setupIPIdentityWatcher.Do(func() {
		go ipIdentityWatcher(listeners)
	})
}
