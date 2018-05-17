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

	// prefixLengths reference-count the number of CIDRs that use
	// particular prefix lengths for the mask.
	v4PrefixLengths map[int]int
	v6PrefixLengths map[int]int
}

// Implementation represents a concrete datapath implementation of the IPCache
// which may restrict the ability to apply IPCache mappings, depending on the
// underlying details of that implementation.
type Implementation interface {
	GetMaxPrefixLengths() int
}

// NewIPCache returns a new IPCache with the mappings of endpoint IP to security
// identity (and vice-versa) initialized.
func NewIPCache() *IPCache {
	return &IPCache{
		ipToIdentityCache: map[string]identity.NumericIdentity{},
		identityToIPCache: map[identity.NumericIdentity]map[string]struct{}{},
		v4PrefixLengths:   map[int]int{},
		v6PrefixLengths:   map[int]int{},
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

func upsertToKVStore(ipKey string, ipIDPair identity.IPIdentityPair) error {
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

	return kvstore.Update(ipKey, marshaledIPIDPair, true)
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

	return upsertToKVStore(ipKey, ipIDPair)
}

// UpsertIPNetToKVStore updates / inserts the provided CIDR->Identity mapping
// into the kvstore, which will subsequently trigger an event in
// ipIdentityWatcher().
func UpsertIPNetToKVStore(prefix *net.IPNet, ID *identity.Identity) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, prefix.String())
	ipIDPair := identity.IPIdentityPair{
		IP:       prefix.IP,
		Mask:     prefix.Mask,
		ID:       ID.ID,
		Metadata: AddressSpace, // XXX: Should we associate more metadata?
	}

	return upsertToKVStore(ipKey, ipIDPair)
}

func checkPrefixLengthsAgainstMap(impl Implementation, prefixes []*net.IPNet, existingPrefixes map[int]int) error {
	prefixLengths := make(map[int]struct{})

	for i := range existingPrefixes {
		prefixLengths[i] = struct{}{}
	}

	for _, prefix := range prefixes {
		ones, _ := prefix.Mask.Size()
		if _, ok := prefixLengths[ones]; !ok {
			prefixLengths[ones] = struct{}{}
		}
	}

	maxPrefixLengths := impl.GetMaxPrefixLengths()
	if len(prefixLengths) > maxPrefixLengths {
		existingPrefixLengths := len(existingPrefixes)
		return fmt.Errorf("Adding specified CIDR prefixes would result in too many prefix lengths (current: %d, result: %d, max: %d)",
			existingPrefixLengths, len(prefixLengths), maxPrefixLengths)
	}
	return nil
}

// CheckPrefixes ensures that we will reject rules if the import of those
// rules would cause the underlying implementation of the ipcache to exceed
// the maximum number of supported CIDR prefix lengths.
func CheckPrefixes(impl Implementation, prefixes []*net.IPNet) (err error) {
	IPIdentityCache.RLock()
	defer IPIdentityCache.RUnlock()

	if err = checkPrefixLengthsAgainstMap(impl, prefixes, IPIdentityCache.v4PrefixLengths); err != nil {
		return
	}
	return checkPrefixLengthsAgainstMap(impl, prefixes, IPIdentityCache.v6PrefixLengths)
}

// UpsertIPNetsToKVStore inserts a CIDR->Identity mapping into the kvstore
// ipcache for each of the specified prefixes and identities. That is to say,
// prefixes[0] is mapped to identities[0].
//
// If any Prefix->Identity mapping cannot be created, it will not create any
// of the mappings and returns an error.
//
// The caller should check the prefix lengths against the underlying IPCache
// implementation using CheckPrefixLengths prior to upserting to the kvstore.
func UpsertIPNetsToKVStore(prefixes []*net.IPNet, identities []*identity.Identity) (err error) {
	if len(prefixes) != len(identities) {
		return fmt.Errorf("Invalid []Prefix->[]Identity ipcache mapping requested: prefixes=%d identities=%d", len(prefixes), len(identities))
	}
	for i, prefix := range prefixes {
		id := identities[i]
		err = UpsertIPNetToKVStore(prefix, id)
		if err != nil {
			for j := 0; j < i; j++ {
				err2 := DeleteIPFromKVStore(prefix.String())
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

// DeleteIPFromKVStore removes the IP->Identity mapping for the specified ip from the
// kvstore, which will subsequently trigger an event in ipIdentityWatcher().
func DeleteIPFromKVStore(ip string) error {
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, ip)
	return kvstore.Delete(ipKey)
}

// DeleteIPNetsFromKVStore removes the Prefix->Identity mappings for the
// specified slice of prefixes from the kvstore, which will subsequently
// trigger an event in ipIdentityWatcher().
func DeleteIPNetsFromKVStore(prefixes []*net.IPNet) (err error) {
	for _, prefix := range prefixes {
		if err2 := DeleteIPFromKVStore(prefix.String()); err2 != nil {
			err = err2
			log.WithFields(logrus.Fields{
				"prefix": prefix.String(),
			}).Error("Failed to delete CIDR->ID mappings")
		}
	}

	return
}

// refPrefixLength adds one reference to the prefix length in the map.
func refPrefixLength(prefixLengths map[int]int, length int) {
	if _, ok := prefixLengths[length]; ok {
		prefixLengths[length]++
	} else {
		prefixLengths[length] = 1
	}
}

// refPrefixLength removes one reference from the prefix length in the map.
func unrefPrefixLength(prefixLengths map[int]int, length int) {
	value, _ := prefixLengths[length]
	if value <= 1 {
		delete(prefixLengths, length)
	} else {
		prefixLengths[length]--
	}
}

// Upsert adds / updates the provided IP (endpoint or CIDR prefix) and identity
// into the IPCache.
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

	// Add a reference for the prefix length if this is a CIDR.
	if _, cidr, err := net.ParseCIDR(IP); err == nil {
		pl, bits := cidr.Mask.Size()
		switch bits {
		case net.IPv6len * 8:
			refPrefixLength(ipc.v6PrefixLengths, pl)
		case net.IPv4len * 8:
			refPrefixLength(ipc.v4PrefixLengths, pl)
		}
	}
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

		// Remove a reference for the prefix length if this is a CIDR.
		if _, cidr, err := net.ParseCIDR(IP); err == nil {
			pl, bits := cidr.Mask.Size()
			switch bits {
			case net.IPv6len * 8:
				unrefPrefixLength(ipc.v6PrefixLengths, pl)
			case net.IPv4len * 8:
				unrefPrefixLength(ipc.v4PrefixLengths, pl)
			}
		}
	}
}

// ToBPFData renders the ipcache into the relevant set of CIDR prefixes for
// the BPF datapath to use for lookup.
func (ipc *IPCache) ToBPFData() (s6, s4 []int) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	s6 = make([]int, 0, len(ipc.v6PrefixLengths))
	s4 = make([]int, 0, len(ipc.v4PrefixLengths))

	// Always include host prefix
	s6 = append(s6, net.IPv6len*8)
	for prefix := range ipc.v6PrefixLengths {
		if prefix != net.IPv6len*8 {
			s6 = append(s6, prefix)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s6)))

	// Always include host prefix
	s4 = append(s4, net.IPv4len*8)
	for prefix := range ipc.v4PrefixLengths {
		if prefix != net.IPv4len*8 {
			s4 = append(s4, prefix)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s4)))

	return
}

// delete removes the provided IP-to-security-identity mapping from the IPCache.
func (ipc *IPCache) delete(IP string) {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	ipc.deleteLocked(IP)
}

// LookupByIP returns the corresponding security identity that endpoint IP maps
// to within the provided IPCache, as well as if the corresponding entry exists
// in the IPCache.
func (ipc *IPCache) LookupByIP(IP string) (identity.NumericIdentity, bool) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	return ipc.LookupByIPRLocked(IP)
}

// LookupByIPRLocked returns the corresponding security identity that endpoint IP maps
// to within the provided IPCache, as well as if the corresponding entry exists
// in the IPCache.
func (ipc *IPCache) LookupByIPRLocked(IP string) (identity.NumericIdentity, bool) {

	identity, exists := ipc.ipToIdentityCache[IP]
	return identity, exists
}

// LookupByPrefixRLocked looks for either the specified CIDR prefix, or if the
// prefix is fully specified (ie, w.x.y.z/32 for IPv4), find the host for the
// identity in the provided IPCache, and returns the corresponding security
// identity as well as whether the entry exists in the IPCache.
func (ipc *IPCache) LookupByPrefixRLocked(prefix string) (identity identity.NumericIdentity, exists bool) {
	if _, cidr, err := net.ParseCIDR(prefix); err == nil {
		// If it's a fully specfied prefix, attempt to find the host
		ones, bits := cidr.Mask.Size()
		if ones == bits {
			identity, exists = ipc.ipToIdentityCache[cidr.IP.String()]
			if exists {
				return
			}
		}
	}
	identity, exists = ipc.ipToIdentityCache[prefix]
	return
}

// LookupByPrefix returns the corresponding security identity that endpoint IP
// maps to within the provided IPCache, as well as if the corresponding entry
// exists in the IPCache.
func (ipc *IPCache) LookupByPrefix(IP string) (identity.NumericIdentity, bool) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	return ipc.LookupByPrefixRLocked(IP)
}

// LookupByIdentity returns the set of IPs (endpoint or CIDR prefix) that have
// security identity ID, as well as whether the corresponding entry exists in
// the IPCache.
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
	// IPCache has changed. If an existing IP->ID mapping is updated, then
	// the old IPIdentityPair will be provided; otherwise it is nil.
	OnIPIdentityCacheChange(modType CacheModification, oldIPIDPair *identity.IPIdentityPair, newIPIDPair identity.IPIdentityPair)

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
					"cached-identity":      cachedIdentity,
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
	setupIPIdentityWatcher.Do(func() {
		go ipIdentityWatcher(listeners)
	})
}
