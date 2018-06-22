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
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var (
	// IPIdentityCache caches the mapping of endpoint IPs to their corresponding
	// security identities across the entire cluster in which this instance of
	// Cilium is running.
	IPIdentityCache = NewIPCache()
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

// checkPrefixes ensures that we will reject rules if the import of those
// rules would cause the underlying implementation of the ipcache to exceed
// the maximum number of supported CIDR prefix lengths.
func checkPrefixes(impl Implementation, prefixes []*net.IPNet) (err error) {
	IPIdentityCache.RLock()
	defer IPIdentityCache.RUnlock()

	if err = checkPrefixLengthsAgainstMap(impl, prefixes, IPIdentityCache.v4PrefixLengths); err != nil {
		return
	}
	return checkPrefixLengthsAgainstMap(impl, prefixes, IPIdentityCache.v6PrefixLengths)
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

// GetIPIdentityMapModel returns all known endpoint IP to security identity mappings
// stored in the key-value store.
func GetIPIdentityMapModel() {
	// TODO (ianvernon) return model of ip to identity mapping. For use in CLI.
	// see GH-2555
}
