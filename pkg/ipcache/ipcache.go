// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
)

// Identity is the identity representation of an IP<->Identity cache.
type Identity struct {
	// Note: The ordering of these fields is optimized to reduce padding

	// Source is the source of the identity in the cache
	Source source.Source

	// overwrittenLegacySource contains the source of the original entry created
	// via legacy API. This is preserved so that original source can be restored
	// if the metadata API stops managing the entry.
	overwrittenLegacySource source.Source

	// ID is the numeric identity
	ID identity.NumericIdentity

	// This blank field ensures that the == operator cannot be used on this
	// type, to avoid external packages accidentally comparing the private
	// values below
	_ []struct{}

	// modifiedByLegacyAPI indicates that this entry touched by the legacy Upsert API.
	// This informs the metadata subsystem to retain the original source and
	// to clean up the entry if the legacy API already dropped its reference.
	// upsertLocked will ensure that this field remains true once set. In other
	// words, there is no way unset this field once set.
	// This field is intended to be removed once cilium/cilium#21142 has been
	// fully implemented and all entries are created via the new metadata API
	modifiedByLegacyAPI bool

	// shadowed determines if another entry overlaps with this one.
	// Shadowed identities are not propagated to listeners by default.
	// Most commonly set for Identity with Source = source.Generated when
	// a pod IP (other source) has the same IP.
	shadowed bool
}

func (i Identity) equals(o Identity) bool {
	return i.ID == o.ID &&
		i.Source == o.Source &&
		i.shadowed == o.shadowed &&
		i.modifiedByLegacyAPI == o.modifiedByLegacyAPI &&
		i.overwrittenLegacySource == o.overwrittenLegacySource
}

func (i Identity) exclusivelyOwnedByLegacyAPI() bool {
	return i.modifiedByLegacyAPI && i.overwrittenLegacySource == ""
}

func (i Identity) exclusivelyOwnedByMetadataAPI() bool {
	return !i.modifiedByLegacyAPI
}

func (i Identity) ownedByLegacyAndMetadataAPI() bool {
	return i.modifiedByLegacyAPI && i.overwrittenLegacySource != ""
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
	NamedPorts types.NamedPortMap
}

// Configuration is init-time configuration for the IPCache.
type Configuration struct {
	context.Context
	// Accessors to other subsystems, provided by the daemon
	cache.IdentityAllocator
	ipcacheTypes.PolicyHandler
	ipcacheTypes.DatapathHandler
	synced.CacheStatus
}

// IPCache is a collection of mappings:
//   - mapping of endpoint IP or CIDR to security identities of all endpoints
//     which are part of the same cluster, and vice-versa
//   - mapping of endpoint IP or CIDR to host IP (maybe nil)
type IPCache struct {
	mutex             lock.SemaphoredMutex
	ipToIdentityCache map[string]Identity
	identityToIPCache map[identity.NumericIdentity]map[string]struct{}
	ipToHostIPCache   map[string]IPKeyPair
	ipToK8sMetadata   map[string]K8sMetadata

	listeners []IPIdentityMappingListener

	// controllers manages the async controllers for this IPCache
	controllers *controller.Manager

	// needNamedPorts is initially 'false', but will atomically be changed to 'true'
	// when the clusterwide named port mappings are needed for network policy
	// computation for the first time. This avoids the overhead of unnecessarily
	// triggering policy updates when it is known not to be needed.
	needNamedPorts atomic.Bool

	// namedPorts is a collection of all named ports in the cluster. This is needed
	// only if an egress policy refers to a port by name.
	// This map is returned (read-only, as a NamedPortMultiMap) to users.
	// Therefore, all updates must be made atomically, which is guaranteed by the
	// interface.
	namedPorts namedPortMultiMapUpdater

	// Configuration provides pointers towards other agent components that
	// the IPCache relies upon at runtime.
	*Configuration

	// metadata is the ipcache identity metadata map, which maps IPs to labels.
	metadata *metadata

	// prefixLengths tracks the unique set of prefix lengths for IPv4 and
	// IPv6 addresses in order to optimize longest prefix match lookups.
	prefixLengths *counter.PrefixLengthCounter

	// injectionStarted is a sync.Once so we can lazily start the prefix injection controller,
	// but only once
	injectionStarted sync.Once
}

// NewIPCache returns a new IPCache with the mappings of endpoint IP to security
// identity (and vice-versa) initialized.
func NewIPCache(c *Configuration) *IPCache {
	ipc := &IPCache{
		mutex:             lock.NewSemaphoredMutex(),
		ipToIdentityCache: map[string]Identity{},
		identityToIPCache: map[identity.NumericIdentity]map[string]struct{}{},
		ipToHostIPCache:   map[string]IPKeyPair{},
		ipToK8sMetadata:   map[string]K8sMetadata{},
		controllers:       controller.NewManager(),
		namedPorts:        types.NewNamedPortMultiMap(),
		metadata:          newMetadata(),
		prefixLengths:     counter.DefaultPrefixLengthCounter(),
		Configuration:     c,
	}
	return ipc
}

// Shutdown cleans up asynchronous routines associated with the IPCache.
func (ipc *IPCache) Shutdown() error {
	return ipc.controllers.RemoveControllerAndWait(LabelInjectorName)
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
func (ipc *IPCache) UpdateController(
	name string,
	params controller.ControllerParams,
) {
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

func (ipc *IPCache) GetHostIPCache(ip string) (net.IP, uint8) {
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	return ipc.getHostIPCache(ip)
}

func (ipc *IPCache) getHostIPCache(ip string) (net.IP, uint8) {
	ipKeyPair := ipc.ipToHostIPCache[ip]
	return ipKeyPair.IP, ipKeyPair.Key
}

// GetK8sMetadata returns Kubernetes metadata for the given IP address.
// The returned pointer should *never* be modified.
func (ipc *IPCache) GetK8sMetadata(ip netip.Addr) *K8sMetadata {
	if !ip.IsValid() {
		return nil
	}
	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()
	return ipc.getK8sMetadata(ip.String())
}

// getK8sMetadata returns Kubernetes metadata for the given IP address.
func (ipc *IPCache) getK8sMetadata(ip string) *K8sMetadata {
	if k8sMeta, ok := ipc.ipToK8sMetadata[ip]; ok {
		return &k8sMeta
	}
	return nil
}

// Upsert adds / updates the provided IP (endpoint or CIDR prefix) and identity
// into the IPCache.
//
// Returns an error if the entry is not owned by the self declared source, i.e.
// returns error if the kubernetes layer is trying to upsert an entry now
// managed by the kvstore layer or if 'ip' is invalid. See
// source.AllowOverwrite() for rules on ownership. hostIP is the location of the
// given IP. It is optional (may be nil) and is propagated to the listeners.
// k8sMeta contains Kubernetes-specific metadata such as pod namespace and pod
// name belonging to the IP (may be nil).
//
// When deleting ipcache entries that were previously inserted via this
// function, ensure that the corresponding delete occurs via Delete().
//
// Deprecated: Prefer UpsertLabels() instead.
func (ipc *IPCache) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) (namedPortsChanged bool, err error) {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	return ipc.upsertLocked(ip, hostIP, hostKey, k8sMeta, newIdentity, false /* !force */, true /* fromLegacyAPI */)
}

// upsertLocked adds / updates the provided IP and identity into the IPCache,
// assuming that the IPCache lock has been taken. Warning, do not use force
// unless you know exactly what you're doing. Forcing adding / updating the
// IPCache will not take into account the source of the identity and bypasses
// the overwrite logic! Once GH-18301 is addressed, there will be no need for
// any force logic.
//
// The ip argument is a string, and the format is one of
// - Prefix (e.g., 10.0.0.0/24)
// - Host IP (e.g., 10.0.0.1)
// - Prefix with ClusterID (e.g., 10.0.0.0/24@1)
// - Host IP with ClusterID (e.g., 10.0.0.1@1)
//
// The formats with ClusterID are only used by Cluster Mesh for overlapping IP
// range support which identifies prefix or host IPs using prefix/ip + ClusterID.
func (ipc *IPCache) upsertLocked(
	ip string,
	hostIP net.IP,
	hostKey uint8,
	k8sMeta *K8sMetadata,
	newIdentity Identity,
	force bool,
	fromLegacyAPI bool,
) (namedPortsChanged bool, err error) {
	var newNamedPorts types.NamedPortMap
	if k8sMeta != nil {
		newNamedPorts = k8sMeta.NamedPorts
	}

	scopedLog := log
	if option.Config.Debug {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.IPAddr:   ip,
			logfields.Identity: &newIdentity,
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

	var cidrCluster cmtypes.PrefixCluster
	var oldIdentity *Identity
	callbackListeners := true

	oldHostIP, oldHostKey := ipc.getHostIPCache(ip)
	oldK8sMeta := ipc.ipToK8sMetadata[ip]
	metaEqual := oldK8sMeta.Equal(k8sMeta)

	cachedIdentity, found := ipc.ipToIdentityCache[ip]
	if found {
		// If this is a legacy upsert call,  then we need to make sure that the
		// overwrittenLegacySource is updated
		if fromLegacyAPI {
			switch {
			case cachedIdentity.exclusivelyOwnedByMetadataAPI():
				// If the entry was exclusively owned by the metadata API, then we
				// want to preserve our source as the legacy source (so it can be
				// restored by the metadata API later) - even if our upsert call is
				// later rejected due to it being a low-precedence upsert.
				newIdentity.overwrittenLegacySource = newIdentity.Source
			case cachedIdentity.ownedByLegacyAndMetadataAPI():
				// If the entry is owned by both APIs, then it will have overwrittenLegacySource
				// already set. Thus, check if we should update it, otherwise just preserve it as is.
				if source.AllowOverwrite(cachedIdentity.overwrittenLegacySource, newIdentity.Source) {
					newIdentity.overwrittenLegacySource = newIdentity.Source
				} else {
					newIdentity.overwrittenLegacySource = cachedIdentity.overwrittenLegacySource
				}
			}
		}

		// Here we track if an entry was previously created via new asynchronous
		// UpsertMetadata API or the old synchronous Upsert call and preserve that bit
		if fromLegacyAPI || cachedIdentity.modifiedByLegacyAPI {
			newIdentity.modifiedByLegacyAPI = true
		}

		if !force && !source.AllowOverwrite(cachedIdentity.Source, newIdentity.Source) {
			metrics.IPCacheErrorsTotal.WithLabelValues(
				metricTypeUpsert, metricErrorOverwrite,
			).Inc()

			// Even if this update is rejected, we want to update the modifiedByLegacyAPI
			// and overwrittenLegacySource fields in case the low precedence source here
			// needs to be restored later
			cachedIdentity.modifiedByLegacyAPI = newIdentity.modifiedByLegacyAPI
			cachedIdentity.overwrittenLegacySource = newIdentity.overwrittenLegacySource
			ipc.ipToIdentityCache[ip] = cachedIdentity

			return false, NewErrOverwrite(cachedIdentity.Source, newIdentity.Source)
		}

		// Skip update if IP is already mapped to the given identity
		// and the host IP hasn't changed.
		if cachedIdentity.equals(newIdentity) && oldHostIP.Equal(hostIP) &&
			hostKey == oldHostKey && metaEqual {
			metrics.IPCacheErrorsTotal.WithLabelValues(
				metricTypeUpsert, metricErrorIdempotent,
			).Inc()
			return false, nil
		}

		oldIdentity = &cachedIdentity
	} else if fromLegacyAPI {
		// If this is a new entry, inserted via legacy API, then track it as such
		newIdentity.modifiedByLegacyAPI = true
	}

	// Endpoint IP identities take precedence over CIDR identities, so if the
	// IP is a full CIDR prefix and there's an existing equivalent endpoint IP,
	// don't notify the listeners.
	if cidrCluster, err = cmtypes.ParsePrefixCluster(ip); err == nil {
		if cidrCluster.IsSingleIP() {
			if _, endpointIPFound := ipc.ipToIdentityCache[cidrCluster.AddrCluster().String()]; endpointIPFound {
				scopedLog.Debug("Ignoring CIDR to identity mapping as it is shadowed by an endpoint IP")
				// Skip calling back the listeners, since the endpoint IP has
				// precedence over the new CIDR.
				newIdentity.shadowed = true
			}
		}
	} else if addrCluster, err := cmtypes.ParseAddrCluster(ip); err == nil { // Endpoint IP or Endpoint IP with ClusterID
		cidrCluster = addrCluster.AsPrefixCluster()

		// Check whether the upserted endpoint IP will shadow that CIDR, and
		// replace its mapping with the listeners if that was the case.
		if !found {
			cidrClusterStr := cidrCluster.String()
			if cidrIdentity, cidrFound := ipc.ipToIdentityCache[cidrClusterStr]; cidrFound {
				oldHostIP, _ = ipc.getHostIPCache(cidrClusterStr)
				if cidrIdentity.ID != newIdentity.ID || !oldHostIP.Equal(hostIP) {
					scopedLog.Debug("New endpoint IP started shadowing existing CIDR to identity mapping")
					cidrIdentity.shadowed = true
					ipc.ipToIdentityCache[cidrClusterStr] = cidrIdentity
					oldIdentity = &cidrIdentity
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
			logfields.AddrCluster: ip,
			logfields.Identity:    newIdentity,
			logfields.Key:         hostKey,
		}).Error("Attempt to upsert invalid IP into ipcache layer")
		metrics.IPCacheErrorsTotal.WithLabelValues(
			metricTypeUpsert, metricErrorInvalid,
		).Inc()
		return false, NewErrInvalidIP(ip)
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
	ipc.prefixLengths.Add([]netip.Prefix{cidrCluster.AsPrefix()})

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
		// Update the named ports reference counting, but don't cause policy
		// updates if no policy uses named ports.
		namedPortsChanged = ipc.namedPorts.Update(oldK8sMeta.NamedPorts, newNamedPorts)
		namedPortsChanged = namedPortsChanged && ipc.needNamedPorts.Load()
	}

	if callbackListeners && !newIdentity.shadowed {
		for _, listener := range ipc.listeners {
			listener.OnIPIdentityCacheChange(Upsert, cidrCluster, oldHostIP, hostIP, oldIdentity, newIdentity, hostKey, k8sMeta)
		}
	}

	metrics.IPCacheEventsTotal.WithLabelValues(
		metricTypeUpsert,
	).Inc()
	return namedPortsChanged, nil
}

// DumpToListener dumps the entire contents of the IPCache by triggering
// the listener's "OnIPIdentityCacheChange" method for each entry in the cache.
func (ipc *IPCache) DumpToListener(listener IPIdentityMappingListener) {
	ipc.RLock()
	ipc.DumpToListenerLocked(listener)
	ipc.RUnlock()
}

// MU is a batched metadata update, the short name is to cut down on visual clutter.
type MU struct {
	Prefix   netip.Prefix
	Source   source.Source
	Resource ipcacheTypes.ResourceID
	Metadata []IPMetadata
}

// UpsertMetadata upserts a given IP and some corresponding information into
// the ipcache metadata map. See IPMetadata for a list of types that are valid
// to pass into this function. This will trigger asynchronous calculation of
// any datapath updates necessary to implement the logic associated with the
// specified metadata.
func (ipc *IPCache) UpsertMetadata(prefix netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID, aux ...IPMetadata) {
	ipc.UpsertMetadataBatch(MU{Prefix: prefix, Source: src, Resource: resource, Metadata: aux})
}

// UpsertMetadataBatch applies updates to multiple prefixes in a single transaction,
// reducing potential lock contention.
//
// Returns a revision number that can be passed to WaitForRevision().
func (ipc *IPCache) UpsertMetadataBatch(updates ...MU) (revision uint64) {
	prefixes := make([]netip.Prefix, 0, len(updates))
	ipc.metadata.Lock()
	for _, upd := range updates {
		prefixes = append(prefixes, ipc.metadata.upsertLocked(upd.Prefix, upd.Source, upd.Resource, upd.Metadata...)...)
	}
	ipc.metadata.Unlock()
	revision = ipc.metadata.enqueuePrefixUpdates(prefixes...)
	ipc.TriggerLabelInjection()
	return
}

// RemoveMetadata removes metadata associated with a specific resource from the
// supplied prefix. Individual metadata types must be supplied for removal, but the
// data need not match.
//
// This removes nothing:
//
//	RemoveMedata(pfx, resource)
//
// This removes all labels from the given resource:
//
//	RemoveMetadata(pfx, resource, Labels{})
func (ipc *IPCache) RemoveMetadata(prefix netip.Prefix, resource ipcacheTypes.ResourceID, aux ...IPMetadata) {
	ipc.RemoveMetadataBatch(MU{Prefix: prefix, Resource: resource, Metadata: aux})
}

// RemoveMetadataBatch is a batched version of RemoveMetadata.
// Returns a revision number that can be passed to WaitForRevision().
func (ipc *IPCache) RemoveMetadataBatch(updates ...MU) (revision uint64) {
	prefixes := make([]netip.Prefix, 0, len(updates))
	ipc.metadata.Lock()
	for _, upd := range updates {
		prefixes = append(prefixes, ipc.metadata.remove(upd.Prefix, upd.Resource, upd.Metadata...)...)
	}
	ipc.metadata.Unlock()
	revision = ipc.metadata.enqueuePrefixUpdates(prefixes...)
	ipc.TriggerLabelInjection()
	return
}

// UpsertPrefixes inserts the prefixes into the IPCache and associates CIDR
// labels with these prefixes, thereby making these prefixes selectable in
// policy via local ("CIDR") identities.
//
// This will trigger asynchronous calculation of any datapath updates necessary
// to implement the logic associated with the new CIDR labels.
//
// Returns a revision number that can be passed to WaitForRevision().
func (ipc *IPCache) UpsertPrefixes(prefixes []netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID) (revision uint64) {
	ipc.metadata.Lock()
	affectedPrefixed := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		affectedPrefixed = append(affectedPrefixed, ipc.metadata.upsertLocked(p, src, resource, labels.GetCIDRLabels(p))...)
	}
	ipc.metadata.Unlock()
	revision = ipc.metadata.enqueuePrefixUpdates(affectedPrefixed...)
	ipc.TriggerLabelInjection()
	return
}

// RemovePrefixes removes the association between the prefixes and the CIDR
// labels corresponding to those prefixes.
//
// This is the reverse operation of UpsertPrefixes(). If multiple callers call
// UpsertPrefixes() with different resources, then RemovePrefixes() will only
// remove the association for the target resource. That is, *all* callers must
// call RemovePrefixes() before this the these prefixes become disassociated
// from the "CIDR" labels.
//
// This will trigger asynchronous calculation of any datapath updates necessary
// to implement the logic associated with the removed CIDR labels.
func (ipc *IPCache) RemovePrefixes(prefixes []netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID) {
	ipc.metadata.Lock()
	affectedPrefixes := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		affectedPrefixes = append(affectedPrefixes, ipc.metadata.remove(p, resource, labels.GetCIDRLabels(p))...)
	}
	ipc.metadata.Unlock()
	ipc.metadata.enqueuePrefixUpdates(affectedPrefixes...)
	ipc.TriggerLabelInjection()
}

// UpsertLabels upserts a given IP and its corresponding labels associated
// with it into the ipcache metadata map. The given labels are not modified nor
// is its reference saved, as they're copied when inserting into the map.
// This will trigger asynchronous calculation of any local identity changes
// that must occur to associate the specified labels with the prefix, and push
// any datapath updates necessary to implement the logic associated with the
// metadata currently associated with the 'prefix'.
func (ipc *IPCache) UpsertLabels(prefix netip.Prefix, lbls labels.Labels, src source.Source, resource ipcacheTypes.ResourceID) {
	ipc.UpsertMetadata(prefix, src, resource, lbls)
}

func (ipc *IPCache) RemoveLabels(cidr netip.Prefix, lbls labels.Labels, resource ipcacheTypes.ResourceID) {
	ipc.RemoveMetadata(cidr, resource, lbls)
}

// OverrideIdentity overrides the identity for a given prefix in the IPCache metadata
// map. This is used when a resource indicates that this prefix already has a
// defined identity, and where any additional labels associated with the prefix
// are to be ignored.
// If multiple resources override the identity, a warning is emitted and only
// one of the override identities is used.
// This will trigger asynchronous calculation of any local identity changes
// that must occur to associate the specified labels with the prefix, and push
// any datapath updates necessary to implement the logic associated with the
// metadata currently associated with the 'prefix'.
//
// Callers must arrange for RemoveIdentityOverride() to eventually be called
// to reverse this operation if the underlying resource is removed.
//
// Use with caution: For most use cases, UpsertLabels() is a better API to
// allow metadata to be associated with the prefix. This will delegate identity
// resolution to the IPCache internally, which provides better compatibility
// between various features that may use the IPCache to associate metadata with
// the same netip prefixes. Using this API may cause feature incompatibilities
// with users of other APIs such as UpsertLabels(), UpsertMetadata() and other
// variations on inserting metadata into the IPCache.
func (ipc *IPCache) OverrideIdentity(prefix netip.Prefix, identityLabels labels.Labels, src source.Source, resource ipcacheTypes.ResourceID) {
	ipc.UpsertMetadata(prefix, src, resource, overrideIdentity(true), identityLabels)
}

func (ipc *IPCache) RemoveIdentityOverride(cidr netip.Prefix, identityLabels labels.Labels, resource ipcacheTypes.ResourceID) {
	ipc.RemoveMetadata(cidr, resource, overrideIdentity(true), identityLabels)
}

// WaitForRevision will block until the desired revision has been reached (or passed).
// It can be used in concert with the revision number returned by Upsert* calls to
// ensure that an update has been applied.
//
// The revision is updated every time the ipcache successfully applies all queued
// metadata updates. Thus, the sequence
//
//	rev := UpsertMetadataBatch(prefix1, metadata, ...)
//	WaitForRevision(ctx, rev)
//
// means that prefix1 has had at least one call to InjectLabels with the supplied
// metadata. It does not guarantee that the metadata matches exactly what was
// passed to UpsertMetadata, as other callers may have also queued modifications.
//
// Note that the revision number should be treated as an opaque identifier.
// Returns a non-nil error if the provided context was cancelled before the
// desired revision was reached.
func (ipc *IPCache) WaitForRevision(ctx context.Context, desired uint64) error {
	return ipc.metadata.waitForRevision(ctx, desired)
}

// DumpToListenerLocked dumps the entire contents of the IPCache by triggering
// the listener's "OnIPIdentityCacheChange" method for each entry in the cache.
// The caller *MUST* grab the IPCache.Lock for reading before calling this
// function.
func (ipc *IPCache) DumpToListenerLocked(listener IPIdentityMappingListener) {
	for ip, identity := range ipc.ipToIdentityCache {
		if identity.shadowed {
			continue
		}
		hostIP, encryptKey := ipc.getHostIPCache(ip)
		k8sMeta := ipc.getK8sMetadata(ip)
		cidrCluster, err := cmtypes.ParsePrefixCluster(ip)
		if err != nil {
			addrCluster := cmtypes.MustParseAddrCluster(ip)
			cidrCluster = addrCluster.AsPrefixCluster()
		}
		listener.OnIPIdentityCacheChange(Upsert, cidrCluster, nil, hostIP, nil, identity, encryptKey, k8sMeta)
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
		scopedLog.Warn("Attempt to remove non-existing IP from ipcache layer")
		metrics.IPCacheErrorsTotal.WithLabelValues(
			metricTypeDelete, metricErrorNoExist,
		).Inc()
		return false
	}

	if cachedIdentity.Source != source {
		scopedLog.WithField("source", cachedIdentity.Source).
			Debugf("Skipping delete of identity from source %s", source)
		metrics.IPCacheErrorsTotal.WithLabelValues(
			metricTypeDelete, metricErrorOverwrite,
		).Inc()
		return false
	}

	var cidrCluster cmtypes.PrefixCluster
	cacheModification := Delete
	oldHostIP, encryptKey := ipc.getHostIPCache(ip)
	oldK8sMeta := ipc.getK8sMetadata(ip)
	var newHostIP net.IP
	var oldIdentity *Identity
	newIdentity := cachedIdentity
	callbackListeners := true

	var err error
	if cidrCluster, err = cmtypes.ParsePrefixCluster(ip); err == nil {
		// Check whether the deleted CIDR was shadowed by an endpoint IP. In
		// this case, skip calling back the listeners since they don't know
		// about its mapping.
		if _, endpointIPFound := ipc.ipToIdentityCache[cidrCluster.AddrCluster().String()]; endpointIPFound {
			scopedLog.Debug("Deleting CIDR shadowed by endpoint IP")
			callbackListeners = false
		}
	} else if addrCluster, err := cmtypes.ParseAddrCluster(ip); err == nil { // Endpoint IP or Endpoint IP with ClusterID
		// Convert the endpoint IP into an equivalent full CIDR.
		cidrCluster = addrCluster.AsPrefixCluster()

		// Check whether the deleted endpoint IP was shadowing that CIDR, and
		// restore its mapping with the listeners if that was the case.
		cidrClusterStr := cidrCluster.String()
		if cidrIdentity, cidrFound := ipc.ipToIdentityCache[cidrClusterStr]; cidrFound {
			newHostIP, _ = ipc.getHostIPCache(cidrClusterStr)
			if cidrIdentity.ID != cachedIdentity.ID || !oldHostIP.Equal(newHostIP) {
				scopedLog.Debug("Removal of endpoint IP revives shadowed CIDR to identity mapping")
				cacheModification = Upsert
				cidrIdentity.shadowed = false
				ipc.ipToIdentityCache[cidrClusterStr] = cidrIdentity
				oldIdentity = &cachedIdentity
				newIdentity = cidrIdentity
			} else {
				// The endpoint IP and the CIDR were associated with the same
				// identity and host IP. Nothing changes for the listeners.
				callbackListeners = false
			}
		}
	} else {
		scopedLog.Error("Attempt to delete invalid IP from ipcache layer")
		metrics.IPCacheErrorsTotal.WithLabelValues(
			metricTypeDelete, metricErrorInvalid,
		).Inc()
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
	ipc.prefixLengths.Delete([]netip.Prefix{cidrCluster.AsPrefix()})

	// Update named ports
	namedPortsChanged = false
	if oldK8sMeta != nil && len(oldK8sMeta.NamedPorts) > 0 {
		namedPortsChanged = ipc.namedPorts.Update(oldK8sMeta.NamedPorts, nil)
		// Only trigger policy updates if named ports are used in policy.
		namedPortsChanged = namedPortsChanged && ipc.needNamedPorts.Load()
	}

	if callbackListeners {
		for _, listener := range ipc.listeners {
			listener.OnIPIdentityCacheChange(cacheModification, cidrCluster, oldHostIP, newHostIP,
				oldIdentity, newIdentity, encryptKey, oldK8sMeta)
		}
	}

	metrics.IPCacheEventsTotal.WithLabelValues(
		metricTypeDelete,
	).Inc()
	return namedPortsChanged
}

// GetNamedPorts returns a copy of the named ports map. May return nil.
func (ipc *IPCache) GetNamedPorts() (npm types.NamedPortMultiMap) {
	// We must not acquire the IPCache mutex here, as that would establish a lock ordering of
	// Endpoint > IPCache (as endpoint.mutex can be held while calling GetNamedPorts)
	// Since InjectLabels requires IPCache > Endpoint, a deadlock can occur otherwise.

	// needNamedPorts is initially set to 'false'. This means that we will not trigger
	// policy updates upon changes to named ports. Once this is set to 'true' though,
	// Upsert and Delete will start to return 'namedPortsChanged = true' if the upsert
	// or delete changed a named port, enabling the caller to trigger a policy update.
	// Note that at the moment, this will never be set back to false, even if no policy
	// uses named ports anymore.
	ipc.needNamedPorts.Store(true)

	// Caller can keep using the map, operations on it are protected by its mutex.
	return ipc.namedPorts
}

// DeleteOnMetadataMatch removes the provided IP to security identity mapping from the IPCache
// if the metadata cache holds the same "owner" metadata as the triggering pod event.
func (ipc *IPCache) DeleteOnMetadataMatch(IP string, source source.Source, namespace, name string) (namedPortsChanged bool) {
	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	k8sMeta := ipc.getK8sMetadata(IP)
	if k8sMeta != nil && k8sMeta.Namespace == namespace && k8sMeta.PodName == name {
		return ipc.deleteLocked(IP, source)
	}
	return false
}

// Delete removes the provided IP-to-security-identity mapping from the IPCache.
//
// Deprecated: Prefer RemoveLabels() or RemoveIdentity() instead.
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

// LookupSecIDByIP performs a longest prefix match lookup in the IPCache for
// the identity corresponding to the specified address (or, in the case of no
// direct match, any shorter prefix). Returns the corresponding identity and
// whether a match was found.
func (ipc *IPCache) LookupSecIDByIP(ip netip.Addr) (id Identity, ok bool) {
	if !ip.IsValid() {
		return Identity{}, false
	}

	ipc.mutex.RLock()
	defer ipc.mutex.RUnlock()

	if id, ok = ipc.LookupByIPRLocked(ip.String()); ok {
		return id, ok
	}

	ipv6Prefixes, ipv4Prefixes := ipc.prefixLengths.ToBPFData()
	prefixes := ipv4Prefixes
	if ip.Is6() {
		prefixes = ipv6Prefixes
	}
	for _, prefixLen := range prefixes {
		// note: we perform a lookup even when `prefixLen == bits`, as some
		// entries derived by a single address cidr-range will not have been
		// found by the above lookup
		cidr, _ := ip.Prefix(prefixLen)
		if id, ok = ipc.LookupByPrefixRLocked(cidr.String()); ok {
			return id, ok
		}
	}
	return id, false
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

// LookupByHostRLocked returns the list of IPs returns the set of IPs
// (endpoint or CIDR prefix) that have hostIPv4 or hostIPv6 associated as the
// host of the entry. Requires the caller to hold the RLock.
func (ipc *IPCache) LookupByHostRLocked(hostIPv4, hostIPv6 net.IP) (cidrs []net.IPNet) {
	for ip, host := range ipc.ipToHostIPCache {
		if hostIPv4 != nil && host.IP.Equal(hostIPv4) || hostIPv6 != nil && host.IP.Equal(hostIPv6) {
			_, cidr, err := net.ParseCIDR(ip)
			if err != nil {
				endpointIP := net.ParseIP(ip)
				cidr = endpointIPToCIDR(endpointIP)
			}
			cidrs = append(cidrs, *cidr)
		}
	}
	return cidrs
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
