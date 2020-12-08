// Copyright 2018-2020 Authors of Cilium
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
	"net"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	"github.com/sirupsen/logrus"
)

var (
	// IPIdentityCache caches the mapping of endpoint IPs to their corresponding
	// security identities across the entire cluster in which this instance of
	// Cilium is running.
	IPIdentityCache = NewIPCache()
)

// Identity is the identity representation of an IP<->Identity cache.
type Identity struct {
	// ID is the numeric identity
	ID identity.NumericIdentity

	// Source is the source of the identity in the cache
	Source source.Source

	// shadowed determines if another entry overlaps with this one.
	// Shadowed identities are not propagated to listeners by default.
	// Most commonly set for Identity with Source = source.Generated when
	// a pod IP (other source) has the same IP.
	shadowed bool
}

// IPKeyPair is the (IP, key) pair used of the identity
type IPKeyPair struct {
	IP  net.IP
	Key uint8
}

// K8sMetadata contains Kubernetes pod information of the IP
type K8sMetadata struct {
	// Namespace is the Kubernetes namespace of the pod behind the IP
	Namespace string
	// PodName is the Kubernetes pod name behind the IP
	PodName string
	// NamedPorts is the set of named ports for the pod
	NamedPorts policy.NamedPortMap
}

// IPCache is a collection of mappings:
// - mapping of endpoint IP or CIDR to security identities of all endpoints
//   which are part of the same cluster, and vice-versa
// - mapping of endpoint IP or CIDR to host IP (maybe nil)
type IPCache struct {
	mutex             lock.SemaphoredMutex
	ipToIdentityCache map[string]Identity
	identityToIPCache map[identity.NumericIdentity]map[string]struct{}
	ipToHostIPCache   map[string]IPKeyPair
	ipToK8sMetadata   map[string]K8sMetadata

	// prefixLengths reference-count the number of CIDRs that use
	// particular prefix lengths for the mask.
	v4PrefixLengths map[int]int
	v6PrefixLengths map[int]int

	listeners []IPIdentityMappingListener

	// controllers manages the async controllers for this IPCache
	controllers *controller.Manager

	// needNamedPorts is initially 'false', but will be changd to 'true' when the
	// clusterwide named port mappings are needed for network policy computation
	// for the first time. This avoids the overhead of maintaining 'namedPorts' map
	// when it is known not to be needed.
	// Protected by 'mutex'.
	needNamedPorts bool

	// namedPorts is a collection of all named ports in the cluster. This is needed
	// only if an egress policy refers to a port by name.
	// This map is returned to users so all updates must be made into a fresh map that
	// is then swapped in place while 'mutex' is being held.
	namedPorts policy.NamedPortMultiMap
}

// NewIPCache returns a new IPCache with the mappings of endpoint IP to security
// identity (and vice-versa) initialized.
func NewIPCache() *IPCache {
	return &IPCache{
		mutex:             lock.NewSemaphoredMutex(),
		ipToIdentityCache: map[string]Identity{},
		identityToIPCache: map[identity.NumericIdentity]map[string]struct{}{},
		ipToHostIPCache:   map[string]IPKeyPair{},
		ipToK8sMetadata:   map[string]K8sMetadata{},
		v4PrefixLengths:   map[int]int{},
		v6PrefixLengths:   map[int]int{},
		controllers:       controller.NewManager(),
		namedPorts:        nil,
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

// AddListener adds a listener for this IPCache.
func (ipc *IPCache) AddListener(listener IPIdentityMappingListener) {
	// We need to acquire the semaphored mutex as we Write Lock as we are
	// modifying the listeners slice.
	ipc.mutex.Lock()
	ipc.listeners = append(ipc.listeners, listener)
	// We will release the semaphore mutex with UnlockToRLock, *and not Unlock*
	// because want to prevent a race across an Upsert or Delete. By doing this
	// we are sure no other writers are performing any operation while we are
	// still reading.
	ipc.mutex.UnlockToRLock()
	defer ipc.mutex.RUnlock()
	// Initialize new listener with the current mappings
	ipc.DumpToListenerLocked(listener)
}

// Update a controller for this IPCache
func (ipc *IPCache) UpdateController(name string, params controller.ControllerParams) {
	ipc.controllers.UpdateController(name, params)
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

func (ipc *IPCache) getHostIPCache(ip string) (net.IP, uint8) {
	ipKeyPair := ipc.ipToHostIPCache[ip]
	return ipKeyPair.IP, ipKeyPair.Key
}

// GetK8sMetadata returns Kubernetes metadata for the given IP address.
// The returned pointer should *never* be modified.
func (ipc *IPCache) GetK8sMetadata(ip string) *K8sMetadata {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	return ipc.getK8sMetadata(ip)
}

// getK8sMetadata returns Kubernetes metadata for the given IP address.
func (ipc *IPCache) getK8sMetadata(ip string) *K8sMetadata {
	if k8sMeta, ok := ipc.ipToK8sMetadata[ip]; ok {
		return &k8sMeta
	}
	return nil
}

// updateNamedPorts accumulates named ports from all K8sMetadata entries to a single map
func (ipc *IPCache) updateNamedPorts() (namedPortsChanged bool) {
	if !ipc.needNamedPorts {
		return false
	}
	// Collect new named Ports
	npm := make(policy.NamedPortMultiMap, len(ipc.namedPorts))
	for _, km := range ipc.ipToK8sMetadata {
		for name, port := range km.NamedPorts {
			if npm[name] == nil {
				npm[name] = make(policy.PortProtoSet)
			}
			npm[name][port] = struct{}{}
		}
	}
	namedPortsChanged = !npm.Equal(ipc.namedPorts)
	if namedPortsChanged {
		// swap the new map in
		if len(npm) == 0 {
			ipc.namedPorts = nil
		} else {
			ipc.namedPorts = npm
		}
	}
	return namedPortsChanged
}

// Upsert adds / updates the provided IP (endpoint or CIDR prefix) and identity
// into the IPCache.
//
// Returns false if the entry is not owned by the self declared source, i.e.
// returns false if the kubernetes layer is trying to upsert an entry now
// managed by the kvstore layer. See source.AllowOverwrite() for rules on
// ownership. hostIP is the location of the given IP. It is optional (may be
// nil) and is propagated to the listeners. k8sMeta contains Kubernetes-specific
// metadata such as pod namespace and pod name belonging to the IP (may be nil).
func (ipc *IPCache) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) (updated bool, namedPortsChanged bool) {
	var newNamedPorts policy.NamedPortMap
	if k8sMeta != nil {
		newNamedPorts = k8sMeta.NamedPorts
	}

	scopedLog := log
	if option.Config.Debug {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.IPAddr:   ip,
			logfields.Identity: newIdentity,
			logfields.Key:      hostKey,
		})
		if k8sMeta != nil {
			scopedLog = scopedLog.WithFields(logrus.Fields{
				logfields.K8sPodName:   k8sMeta.PodName,
				logfields.K8sNamespace: k8sMeta.Namespace,
				logfields.NamedPorts:   k8sMeta.NamedPorts,
			})
		}
	}

	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()

	var cidr *net.IPNet
	var oldIdentity *identity.NumericIdentity
	callbackListeners := true

	oldHostIP, oldHostKey := ipc.getHostIPCache(ip)
	oldK8sMeta := ipc.ipToK8sMetadata[ip]
	metaEqual := oldK8sMeta.Equal(k8sMeta)

	cachedIdentity, found := ipc.ipToIdentityCache[ip]
	if found {
		if !source.AllowOverwrite(cachedIdentity.Source, newIdentity.Source) {
			return false, false
		}

		// Skip update if IP is already mapped to the given identity
		// and the host IP hasn't changed.
		if cachedIdentity == newIdentity && oldHostIP.Equal(hostIP) &&
			hostKey == oldHostKey && metaEqual {
			return true, false
		}

		oldIdentity = &cachedIdentity.ID
	}

	// Endpoint IP identities take precedence over CIDR identities, so if the
	// IP is a full CIDR prefix and there's an existing equivalent endpoint IP,
	// don't notify the listeners.
	var err error
	if _, cidr, err = net.ParseCIDR(ip); err == nil {
		ones, bits := cidr.Mask.Size()
		if ones == bits {
			if _, endpointIPFound := ipc.ipToIdentityCache[cidr.IP.String()]; endpointIPFound {
				scopedLog.Debug("Ignoring CIDR to identity mapping as it is shadowed by an endpoint IP")
				// Skip calling back the listeners, since the endpoint IP has
				// precedence over the new CIDR.
				newIdentity.shadowed = true
			}
		}
	} else if endpointIP := net.ParseIP(ip); endpointIP != nil { // Endpoint IP.
		cidr = endpointIPToCIDR(endpointIP)

		// Check whether the upserted endpoint IP will shadow that CIDR, and
		// replace its mapping with the listeners if that was the case.
		if !found {
			cidrStr := cidr.String()
			if cidrIdentity, cidrFound := ipc.ipToIdentityCache[cidrStr]; cidrFound {
				oldHostIP, _ = ipc.getHostIPCache(cidrStr)
				if cidrIdentity.ID != newIdentity.ID || !oldHostIP.Equal(hostIP) {
					scopedLog.Debug("New endpoint IP started shadowing existing CIDR to identity mapping")
					cidrIdentity.shadowed = true
					ipc.ipToIdentityCache[cidrStr] = cidrIdentity
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
		log.WithFields(logrus.Fields{
			logfields.IPAddr:   ip,
			logfields.Identity: newIdentity,
			logfields.Key:      hostKey,
		}).Error("Attempt to upsert invalid IP into ipcache layer")
		return false, false
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
		ipc.ipToHostIPCache[ip] = IPKeyPair{IP: hostIP, Key: hostKey}
	}

	if !metaEqual {
		if k8sMeta == nil {
			delete(ipc.ipToK8sMetadata, ip)
		} else {
			ipc.ipToK8sMetadata[ip] = *k8sMeta
		}

		// Update named ports, first check for deleted values
		for k := range oldK8sMeta.NamedPorts {
			if _, ok := newNamedPorts[k]; !ok {
				namedPortsChanged = true
				break
			}
		}
		if !namedPortsChanged {
			// Check for added new or changed entries
			for k, v := range newNamedPorts {
				if v2, ok := oldK8sMeta.NamedPorts[k]; !ok || v2 != v {
					namedPortsChanged = true
					break
				}
			}
		}
		if namedPortsChanged {
			// It is possible that some other POD defines same values, check if
			// anything changes over all the PODs.
			namedPortsChanged = ipc.updateNamedPorts()
		}
	}

	if callbackListeners && !newIdentity.shadowed {
		for _, listener := range ipc.listeners {
			listener.OnIPIdentityCacheChange(Upsert, *cidr, oldHostIP, hostIP, oldIdentity, newIdentity.ID, hostKey, k8sMeta)
		}
	}

	return true, namedPortsChanged
}

// DumpToListenerLocked dumps the entire contents of the IPCache by triggering
// the listener's "OnIPIdentityCacheChange" method for each entry in the cache.
func (ipc *IPCache) DumpToListenerLocked(listener IPIdentityMappingListener) {
	for ip, identity := range ipc.ipToIdentityCache {
		if identity.shadowed {
			continue
		}
		hostIP, encryptKey := ipc.getHostIPCache(ip)
		k8sMeta := ipc.getK8sMetadata(ip)
		_, cidr, err := net.ParseCIDR(ip)
		if err != nil {
			endpointIP := net.ParseIP(ip)
			cidr = endpointIPToCIDR(endpointIP)
		}
		listener.OnIPIdentityCacheChange(Upsert, *cidr, nil, hostIP, nil, identity.ID, encryptKey, k8sMeta)
	}
}

// deleteLocked removes the provided IP-to-security-identity mapping
// from ipc with the assumption that the IPCache's mutex is held.
func (ipc *IPCache) deleteLocked(ip string, source source.Source) (namedPortsChanged bool) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr: ip,
	})

	cachedIdentity, found := ipc.ipToIdentityCache[ip]
	if !found {
		scopedLog.Debug("Attempt to remove non-existing IP from ipcache layer")
		return false
	}

	if cachedIdentity.Source != source {
		scopedLog.WithField("source", cachedIdentity.Source).
			Debugf("Skipping delete of identity from source %s", source)
		return false
	}

	var cidr *net.IPNet
	cacheModification := Delete
	oldHostIP, encryptKey := ipc.getHostIPCache(ip)
	oldK8sMeta := ipc.getK8sMetadata(ip)
	var newHostIP net.IP
	var oldIdentity *identity.NumericIdentity
	newIdentity := cachedIdentity
	callbackListeners := true

	var err error
	if _, cidr, err = net.ParseCIDR(ip); err == nil {
		// Check whether the deleted CIDR was shadowed by an endpoint IP. In
		// this case, skip calling back the listeners since they don't know
		// about its mapping.
		if _, endpointIPFound := ipc.ipToIdentityCache[cidr.IP.String()]; endpointIPFound {
			scopedLog.Debug("Deleting CIDR shadowed by endpoint IP")
			callbackListeners = false
		}
	} else if endpointIP := net.ParseIP(ip); endpointIP != nil { // Endpoint IP.
		// Convert the endpoint IP into an equivalent full CIDR.
		cidr = endpointIPToCIDR(endpointIP)

		// Check whether the deleted endpoint IP was shadowing that CIDR, and
		// restore its mapping with the listeners if that was the case.
		cidrStr := cidr.String()
		if cidrIdentity, cidrFound := ipc.ipToIdentityCache[cidrStr]; cidrFound {
			newHostIP, _ = ipc.getHostIPCache(cidrStr)
			if cidrIdentity.ID != cachedIdentity.ID || !oldHostIP.Equal(newHostIP) {
				scopedLog.Debug("Removal of endpoint IP revives shadowed CIDR to identity mapping")
				cacheModification = Upsert
				cidrIdentity.shadowed = false
				ipc.ipToIdentityCache[cidrStr] = cidrIdentity
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
		return false
	}

	scopedLog.Debug("Deleting IP from ipcache layer")

	delete(ipc.ipToIdentityCache, ip)
	delete(ipc.identityToIPCache[cachedIdentity.ID], ip)
	if len(ipc.identityToIPCache[cachedIdentity.ID]) == 0 {
		delete(ipc.identityToIPCache, cachedIdentity.ID)
	}
	delete(ipc.ipToHostIPCache, ip)
	delete(ipc.ipToK8sMetadata, ip)

	// Update named ports
	namedPortsChanged = false
	if oldK8sMeta != nil && len(oldK8sMeta.NamedPorts) > 0 {
		namedPortsChanged = ipc.updateNamedPorts()
	}

	if callbackListeners {
		for _, listener := range ipc.listeners {
			listener.OnIPIdentityCacheChange(cacheModification, *cidr, oldHostIP, newHostIP,
				oldIdentity, newIdentity.ID, encryptKey, oldK8sMeta)
		}
	}

	return namedPortsChanged
}

// GetNamedPorts returns a copy of the named ports map. May return nil.
func (ipc *IPCache) GetNamedPorts() (npm policy.NamedPortMultiMap) {
	ipc.mutex.Lock()
	if !ipc.needNamedPorts {
		ipc.needNamedPorts = true
		ipc.updateNamedPorts()
	}
	// Caller can keep using the map after the lock is released, as the map is never changed
	// once published.
	npm = ipc.namedPorts
	ipc.mutex.Unlock()
	return npm
}

// Delete removes the provided IP-to-security-identity mapping from the IPCache.
func (ipc *IPCache) Delete(IP string, source source.Source) (namedPortsChanged bool) {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	return ipc.deleteLocked(IP, source)
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
// security identity ID, or nil if the entry does not exist.
func (ipc *IPCache) LookupByIdentity(id identity.NumericIdentity) (ips []string) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	// Can't return the internal map as it may be modified at any time when the
	// lock is not held, so return a slice of strings instead
	length := len(ipc.identityToIPCache[id])
	if length > 0 {
		ips = make([]string, 0, length)
		for ip := range ipc.identityToIPCache[id] {
			ips = append(ips, ip)
		}
	}
	return ips
}

// GetIPIdentityMapModel returns all known endpoint IP to security identity mappings
// stored in the key-value store.
func GetIPIdentityMapModel() {
	// TODO (ianvernon) return model of ip to identity mapping. For use in CLI.
	// see GH-2555
}

// Equal returns true if two K8sMetadata pointers contain the same data or are
// both nil.
func (m *K8sMetadata) Equal(o *K8sMetadata) bool {
	if m == o {
		return true
	} else if m == nil || o == nil {
		return false
	}
	if len(m.NamedPorts) != len(o.NamedPorts) {
		return false
	}
	for k, v := range m.NamedPorts {
		if v2, ok := o.NamedPorts[k]; !ok || v != v2 {
			return false
		}
	}
	return m.Namespace == o.Namespace && m.PodName == o.PodName
}
