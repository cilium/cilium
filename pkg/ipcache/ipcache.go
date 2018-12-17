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
	"bytes"
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

// Source is the description of the source of an identity
type Source string

const (
	// FromKubernetes is the source used for identities derived from k8s
	// resources (pods)
	FromKubernetes Source = "k8s"

	// FromKVStore is the source used for identities derived from the
	// kvstore
	FromKVStore Source = "kvstore"

	// FromAgentLocal is the source used for identities derived during the
	// agent bootup process. This includes identities for endpoint IPs.
	FromAgentLocal Source = "agent-local"

	// FromCIDR is the source used for identities that have been derived
	// from local CIDR representations
	FromCIDR Source = "cidr"
)

// Identity is the identity representation of an IP<->Identity cache.
type Identity struct {
	// ID is the numeric identity
	ID identity.NumericIdentity

	// Source is the source of the identity in the cache
	Source Source
}

// IPCache is a collection of mappings:
// - mapping of endpoint IP or CIDR to security identities of all endpoints
//   which are part of the same cluster, and vice-versa
// - mapping of endpoint IP or CIDR to host IP (maybe nil)
type IPCache struct {
	mutex             lock.RWMutex
	ipToIdentityCache map[string]Identity
	identityToIPCache map[identity.NumericIdentity]map[string]struct{}
	ipToHostIPCache   map[string]net.IP

	// prefixLengths reference-count the number of CIDRs that use
	// particular prefix lengths for the mask.
	v4PrefixLengths map[int]int
	v6PrefixLengths map[int]int

	listeners []IPIdentityMappingListener
}

// Implementation represents a concrete datapath implementation of the IPCache
// which may restrict the ability to apply IPCache mappings, depending on the
// underlying details of that implementation.
type Implementation interface {
	GetMaxPrefixLengths(ipv6 bool) int
}

// NewIPCache returns a new IPCache with the mappings of endpoint IP to security
// identity (and vice-versa) initialized.
func NewIPCache() *IPCache {
	return &IPCache{
		ipToIdentityCache: map[string]Identity{},
		identityToIPCache: map[identity.NumericIdentity]map[string]struct{}{},
		ipToHostIPCache:   map[string]net.IP{},
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

// SetListeners sets the listeners for this IPCache.
func (ipc *IPCache) SetListeners(listeners []IPIdentityMappingListener) {
	ipc.mutex.Lock()
	ipc.listeners = listeners
	ipc.mutex.Unlock()
}

func checkPrefixLengthsAgainstMap(impl Implementation, prefixes []*net.IPNet, existingPrefixes map[int]int, isIPv6 bool) error {
	prefixLengths := make(map[int]struct{})

	for i := range existingPrefixes {
		prefixLengths[i] = struct{}{}
	}

	for _, prefix := range prefixes {
		ones, bits := prefix.Mask.Size()
		if _, ok := prefixLengths[ones]; !ok {
			if bits == net.IPv6len*8 && isIPv6 || bits == net.IPv4len*8 && !isIPv6 {
				prefixLengths[ones] = struct{}{}
			}
		}
	}

	maxPrefixLengths := impl.GetMaxPrefixLengths(isIPv6)
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

	if err = checkPrefixLengthsAgainstMap(impl, prefixes, IPIdentityCache.v4PrefixLengths, false); err != nil {
		return
	}
	return checkPrefixLengthsAgainstMap(impl, prefixes, IPIdentityCache.v6PrefixLengths, true)
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

func allowOverwrite(existing, new Source) bool {
	switch existing {
	case FromKubernetes:
		return new != FromCIDR
	case FromKVStore:
		return new == FromKVStore || new == FromAgentLocal
	case FromAgentLocal:
		return new == FromAgentLocal

	case FromCIDR:
		return new == FromCIDR
	}

	return true
}

// endpointIPToCIDR converts the endpoint IP into an equivalent full CIDR.
func endpointIPToCIDR(ip net.IP) *net.IPNet {
	bits := net.IPv6len * 8
	if ip.To4() != nil {
		bits = net.IPv4len * 8
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(bits, bits),
	}
}

// Upsert adds / updates the provided IP (endpoint or CIDR prefix) and identity
// into the IPCache.
//
// Returns false if the entry is not owned by the self declared source, i.e.
// returns false if the kubernetes layer is trying to upsert an entry now
// managed by the kvstore layer. See allowOverwrite() for rules on ownership.
// hostIP is the location of the given IP. It is optional (may be nil) and is
// propagated to the listeners.
func (ipc *IPCache) Upsert(ip string, hostIP net.IP, newIdentity Identity) bool {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr:   ip,
		logfields.Identity: newIdentity,
	})

	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()

	var cidr *net.IPNet
	var oldIdentity *identity.NumericIdentity
	callbackListeners := true

	oldHostIP := ipc.ipToHostIPCache[ip]

	cachedIdentity, found := ipc.ipToIdentityCache[ip]
	if found {
		if !allowOverwrite(cachedIdentity.Source, newIdentity.Source) {
			return false
		}

		// Skip update if IP is already mapped to the given identity
		// and the host IP hasn't changed.
		if cachedIdentity == newIdentity && bytes.Compare(oldHostIP, hostIP) == 0 {
			return true
		}

		oldIdentity = &cachedIdentity.ID
	}

	// Endpoint IP identities take precedence over CIDR identities, so if the
	// IP is a full CIDR prefix and there's an existing equivalent endpoint IP,
	// don't notify the listeners.
	var err error
	if _, cidr, err = net.ParseCIDR(ip); err == nil {
		// Add a reference for the prefix length if this is a CIDR.
		pl, bits := cidr.Mask.Size()
		switch bits {
		case net.IPv6len * 8:
			refPrefixLength(ipc.v6PrefixLengths, pl)
		case net.IPv4len * 8:
			refPrefixLength(ipc.v4PrefixLengths, pl)
		}

		ones, bits := cidr.Mask.Size()
		if ones == bits {
			if _, endpointIPFound := ipc.ipToIdentityCache[cidr.IP.String()]; endpointIPFound {
				scopedLog.Debug("Ignoring CIDR to identity mapping as it is shadowed by an endpoint IP")
				// Skip calling back the listeners, since the endpoint IP has
				// precedence over the new CIDR.
				callbackListeners = false
			}
		}
	} else if endpointIP := net.ParseIP(ip); endpointIP != nil { // Endpoint IP.
		cidr = endpointIPToCIDR(endpointIP)

		// Check whether the upserted endpoint IP will shadow that CIDR, and
		// replace its mapping with the listeners if that was the case.
		if !found {
			cidrStr := cidr.String()
			if cidrIdentity, cidrFound := ipc.ipToIdentityCache[cidrStr]; cidrFound {
				oldHostIP = ipc.ipToHostIPCache[cidrStr]
				if cidrIdentity.ID != newIdentity.ID || bytes.Compare(oldHostIP, hostIP) != 0 {
					scopedLog.Debug("New endpoint IP started shadowing existing CIDR to identity mapping")
					oldIdentity = &cidrIdentity.ID
				} else {
					// The endpoint IP and the CIDR are associated with the
					// same identity and host IP. Nothing changes for the
					// listeners.
					callbackListeners = false
				}
			}
		}
	} else {
		scopedLog.Error("Attempt to upsert invalid IP into ipcache layer")
		return false
	}

	scopedLog.Debug("Upserting IP into ipcache layer")

	// Update both maps.
	ipc.ipToIdentityCache[ip] = newIdentity
	// Delete the old identity, if any.
	if found {
		delete(ipc.identityToIPCache[cachedIdentity.ID], ip)
		if len(ipc.identityToIPCache[cachedIdentity.ID]) == 0 {
			delete(ipc.identityToIPCache, cachedIdentity.ID)
		}
	}
	if _, ok := ipc.identityToIPCache[newIdentity.ID]; !ok {
		ipc.identityToIPCache[newIdentity.ID] = map[string]struct{}{}
	}
	ipc.identityToIPCache[newIdentity.ID][ip] = struct{}{}

	if hostIP == nil {
		delete(ipc.ipToHostIPCache, ip)
	} else {
		ipc.ipToHostIPCache[ip] = hostIP
	}

	if callbackListeners {
		for _, listener := range ipc.listeners {
			listener.OnIPIdentityCacheChange(Upsert, *cidr, oldHostIP, hostIP, oldIdentity, newIdentity.ID)
		}
	}

	return true
}

// DumpToListenerLocked dumps the entire contents of the IPCache by triggering
// the listener's "OnIPIdentityCacheChange" method for each entry in the cache.
func (ipc *IPCache) DumpToListenerLocked(listener IPIdentityMappingListener) {
	for ip, identity := range ipc.ipToIdentityCache {
		hostIP := ipc.ipToHostIPCache[ip]
		_, cidr, err := net.ParseCIDR(ip)
		if err != nil {
			endpointIP := net.ParseIP(ip)
			cidr = endpointIPToCIDR(endpointIP)
		}
		listener.OnIPIdentityCacheChange(Upsert, *cidr, nil, hostIP, nil, identity.ID)
	}
}

// deleteLocked removes removes the provided IP-to-security-identity mapping
// from ipc with the assumption that the IPCache's mutex is held.
func (ipc *IPCache) deleteLocked(ip string, source Source) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr: ip,
	})

	cachedIdentity, found := ipc.ipToIdentityCache[ip]
	if !found {
		scopedLog.Debug("Attempt to remove non-existing IP from ipcache layer")
		return
	}

	if cachedIdentity.Source != source {
		scopedLog.WithField("source", cachedIdentity.Source).
			Debugf("Skipping delete of identity from source %s", source)
		return
	}

	var cidr *net.IPNet
	cacheModification := Delete
	oldHostIP := ipc.ipToHostIPCache[ip]
	var newHostIP net.IP
	var oldIdentity *identity.NumericIdentity
	newIdentity := cachedIdentity
	callbackListeners := true

	var err error
	if _, cidr, err = net.ParseCIDR(ip); err == nil {
		// Remove a reference for the prefix length if this is a CIDR.
		pl, bits := cidr.Mask.Size()
		switch bits {
		case net.IPv6len * 8:
			unrefPrefixLength(ipc.v6PrefixLengths, pl)
		case net.IPv4len * 8:
			unrefPrefixLength(ipc.v4PrefixLengths, pl)
		}

		// Check whether the deleted CIDR was shadowed by an endpoint IP. In
		// this case, skip calling back the listeners since they don't know
		// about its mapping.
		if _, endpointIPFound := ipc.ipToIdentityCache[cidr.IP.String()]; endpointIPFound {
			scopedLog.Debug("Deleting CIDR shadowed by endpoint IP")
			callbackListeners = false
		}
	} else if endpointIP := net.ParseIP(ip); endpointIP != nil { // Endpoint IP.
		// Convert the endpoint IP into an equivalent full CIDR.
		bits := net.IPv6len * 8
		if endpointIP.To4() != nil {
			bits = net.IPv4len * 8
		}
		cidr = &net.IPNet{
			IP:   endpointIP,
			Mask: net.CIDRMask(bits, bits),
		}

		// Check whether the deleted endpoint IP was shadowing that CIDR, and
		// restore its mapping with the listeners if that was the case.
		cidrStr := cidr.String()
		if cidrIdentity, cidrFound := ipc.ipToIdentityCache[cidrStr]; cidrFound {
			newHostIP = ipc.ipToHostIPCache[cidrStr]
			if cidrIdentity.ID != cachedIdentity.ID || bytes.Compare(oldHostIP, newHostIP) != 0 {
				scopedLog.Debug("Removal of endpoint IP revives shadowed CIDR to identity mapping")
				cacheModification = Upsert
				oldIdentity = &cachedIdentity.ID
				newIdentity = cidrIdentity
			} else {
				// The endpoint IP and the CIDR were associated with the same
				// identity and host IP. Nothing changes for the listeners.
				callbackListeners = false
			}
		}
	} else {
		scopedLog.Error("Attempt to delete invalid IP from ipcache layer")
		return
	}

	scopedLog.Debug("Deleting IP from ipcache layer")

	delete(ipc.ipToIdentityCache, ip)
	delete(ipc.identityToIPCache[cachedIdentity.ID], ip)
	if len(ipc.identityToIPCache[cachedIdentity.ID]) == 0 {
		delete(ipc.identityToIPCache, cachedIdentity.ID)
	}
	delete(ipc.ipToHostIPCache, ip)

	if callbackListeners {
		for _, listener := range ipc.listeners {
			listener.OnIPIdentityCacheChange(cacheModification, *cidr, oldHostIP, newHostIP,
				oldIdentity, newIdentity.ID)
		}
	}
}

// Delete removes the provided IP-to-security-identity mapping from the IPCache.
func (ipc *IPCache) Delete(IP string, source Source) {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	ipc.deleteLocked(IP, source)
}

// LookupByIP returns the corresponding security identity that endpoint IP maps
// to within the provided IPCache, as well as if the corresponding entry exists
// in the IPCache.
func (ipc *IPCache) LookupByIP(IP string) (Identity, bool) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	return ipc.LookupByIPRLocked(IP)
}

// LookupByIPRLocked returns the corresponding security identity that endpoint IP maps
// to within the provided IPCache, as well as if the corresponding entry exists
// in the IPCache.
func (ipc *IPCache) LookupByIPRLocked(IP string) (Identity, bool) {

	identity, exists := ipc.ipToIdentityCache[IP]
	return identity, exists
}

// LookupByPrefixRLocked looks for either the specified CIDR prefix, or if the
// prefix is fully specified (ie, w.x.y.z/32 for IPv4), find the host for the
// identity in the provided IPCache, and returns the corresponding security
// identity as well as whether the entry exists in the IPCache.
func (ipc *IPCache) LookupByPrefixRLocked(prefix string) (identity Identity, exists bool) {
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
func (ipc *IPCache) LookupByPrefix(IP string) (Identity, bool) {
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
