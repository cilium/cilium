// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"net"
	"net/netip"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// scIdentity is the information we need about a an identity that rules can select
type scIdentity struct {
	NID       identity.NumericIdentity
	lbls      labels.LabelArray
	nets      []*net.IPNet // Most specific CIDR for the identity, if any.
	computed  bool         // nets has been computed
	namespace string       // value of the namespace label, or ""
}

// scIdentityCache is a cache of Identities keyed by the numeric identity
type scIdentityCache map[identity.NumericIdentity]scIdentity

func newIdentity(nid identity.NumericIdentity, lbls labels.LabelArray) scIdentity {
	return scIdentity{
		NID:       nid,
		lbls:      lbls,
		nets:      getLocalScopeNets(nid, lbls),
		namespace: lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
		computed:  true,
	}
}

// getLocalScopeNets returns the most specific CIDR for a local scope identity.
func getLocalScopeNets(id identity.NumericIdentity, lbls labels.LabelArray) []*net.IPNet {
	if id.HasLocalScope() {
		var (
			maskSize         int
			mostSpecificCidr *net.IPNet
		)
		for _, lbl := range lbls {
			if lbl.Source == labels.LabelSourceCIDR {
				_, netIP, err := net.ParseCIDR(lbl.Key)
				if err == nil {
					if ms, _ := netIP.Mask.Size(); ms > maskSize {
						mostSpecificCidr = netIP
						maskSize = ms
					}
				}
			}
		}
		if mostSpecificCidr != nil {
			return []*net.IPNet{mostSpecificCidr}
		}
	}
	return nil
}

func getIdentityCache(ids cache.IdentityCache) scIdentityCache {
	idCache := make(map[identity.NumericIdentity]scIdentity, len(ids))
	for nid, lbls := range ids {
		idCache[nid] = newIdentity(nid, lbls)
	}
	return idCache
}

// userNotification stores the information needed to call
// IdentitySelectionUpdated callbacks to notify users of selector's
// identity changes. These are queued to be able to call the callbacks
// in FIFO order while not holding any locks.
type userNotification struct {
	user     CachedSelectionUser
	selector CachedSelector
	added    []identity.NumericIdentity
	deleted  []identity.NumericIdentity
	wg       *sync.WaitGroup
}

// SelectorCache caches identities, identity selectors, and the
// subsets of identities each selector selects.
type SelectorCache struct {
	mutex lock.RWMutex

	// idAllocator is used to allocate and release identities. It is used
	// by the NameManager to manage identities corresponding to FQDNs.
	idAllocator cache.IdentityAllocator

	// idCache contains all known identities as informed by the
	// kv-store and the local identity facility via our
	// UpdateIdentities() function.
	idCache scIdentityCache

	// map key is the string representation of the selector being cached.
	selectors map[string]*identitySelector

	localIdentityNotifier identityNotifier

	// userCond is a condition variable for receiving signals
	// about addition of new elements in userNotes
	userCond *sync.Cond
	// userMutex protects userNotes and is linked to userCond
	userMutex lock.Mutex
	// userNotes holds a FIFO list of user notifications to be made
	userNotes []userNotification

	// used to lazily start the handler for user notifications.
	startNotificationsHandlerOnce sync.Once
}

// GetModel returns the API model of the SelectorCache.
func (sc *SelectorCache) GetModel() models.SelectorCache {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	selCacheMdl := make(models.SelectorCache, 0, len(sc.selectors))

	for selector, idSel := range sc.selectors {
		selections := idSel.GetSelections()
		ids := make([]int64, 0, len(selections))
		for i := range selections {
			ids = append(ids, int64(selections[i]))
		}
		selMdl := &models.SelectorIdentityMapping{
			Selector:   selector,
			Identities: ids,
			Users:      int64(idSel.numUsers()),
			Labels:     labelArrayToModel(idSel.GetMetadataLabels()),
		}
		selCacheMdl = append(selCacheMdl, selMdl)
	}

	return selCacheMdl
}

func labelArrayToModel(arr labels.LabelArray) models.LabelArray {
	lbls := make(models.LabelArray, 0, len(arr))
	for _, l := range arr {
		lbls = append(lbls, &models.Label{
			Key:    l.Key,
			Value:  l.Value,
			Source: l.Source,
		})
	}
	return lbls
}

func (sc *SelectorCache) handleUserNotifications() {
	for {
		sc.userMutex.Lock()
		for len(sc.userNotes) == 0 {
			sc.userCond.Wait()
		}
		// get the current batch of notifications and release the lock so that SelectorCache
		// can't block on userMutex while we call IdentitySelectionUpdated callbacks below.
		notifications := sc.userNotes
		sc.userNotes = nil
		sc.userMutex.Unlock()

		for _, n := range notifications {
			n.user.IdentitySelectionUpdated(n.selector, n.added, n.deleted)
			n.wg.Done()
		}
	}
}

func (sc *SelectorCache) queueUserNotification(user CachedSelectionUser, selector CachedSelector, added, deleted []identity.NumericIdentity, wg *sync.WaitGroup) {
	sc.startNotificationsHandlerOnce.Do(func() {
		go sc.handleUserNotifications()
	})
	wg.Add(1)
	sc.userMutex.Lock()
	sc.userNotes = append(sc.userNotes, userNotification{
		user:     user,
		selector: selector,
		added:    added,
		deleted:  deleted,
		wg:       wg,
	})
	sc.userMutex.Unlock()
	sc.userCond.Signal()
}

// NewSelectorCache creates a new SelectorCache with the given identities.
func NewSelectorCache(allocator cache.IdentityAllocator, ids cache.IdentityCache) *SelectorCache {
	sc := &SelectorCache{
		idAllocator: allocator,
		idCache:     getIdentityCache(ids),
		selectors:   make(map[string]*identitySelector),
	}
	sc.userCond = sync.NewCond(&sc.userMutex)
	return sc
}

// SetLocalIdentityNotifier injects the provided identityNotifier into the
// SelectorCache. Currently, this is used to inject the FQDN subsystem into
// the SelectorCache so the SelectorCache can notify the FQDN subsystem when
// it should be aware of a given FQDNSelector for which CIDR identities need
// to be provided upon DNS lookups which corespond to said FQDNSelector.
func (sc *SelectorCache) SetLocalIdentityNotifier(pop identityNotifier) {
	sc.localIdentityNotifier = pop
}

var (
	// Empty slice of numeric identities used for all selectors that select nothing
	emptySelection identity.NumericIdentitySlice
	// wildcardSelectorKey is used to compare if a key is for a wildcard
	wildcardSelectorKey = api.WildcardEndpointSelector.LabelSelector.String()
	// noneSelectorKey is used to compare if a key is for "reserved:none"
	noneSelectorKey = api.EndpointSelectorNone.LabelSelector.String()
)

// identityNotifier provides a means for other subsystems to be made aware of a
// given FQDNSelector (currently pkg/fqdn) so that said subsystems can notify
// the SelectorCache about new IPs (via CIDR Identities) which correspond to
// said FQDNSelector. This is necessary since there is nothing intrinsic to a
// CIDR Identity that says that it corresponds to a given FQDNSelector; this
// relationship is contained only via DNS responses, which are handled
// externally.
type identityNotifier interface {
	// Lock must be held during any calls to *Locked functions below.
	Lock()

	// Unlock must be called after calls to *Locked functions below.
	Unlock()

	// RegisterForIPUpdatesLocked exposes this FQDNSelector so that identities
	// for IPs contained in a DNS response that matches said selector can
	// be propagated back to the SelectorCache via `UpdateFQDNSelector`.
	//
	// This function should only be called when the SelectorCache has been
	// made aware of the FQDNSelector for the first time; subsequent
	// updates to the selectors should be made via `UpdateFQDNSelector`.
	//
	// This function returns the set of IPs for which this selector already applies.
	RegisterForIPUpdatesLocked(selector api.FQDNSelector) []netip.Addr

	// UnregisterForIPUpdatesLocked removes this FQDNSelector from the set of
	// FQDNSelectors which are being tracked by the identityNotifier. The result
	// of this is that no more updates for IPs which correspond to said selector
	// are propagated back to the SelectorCache via `UpdateFQDNSelector`.
	// This occurs when there are no more users of a given FQDNSelector for the
	// SelectorCache.
	UnregisterForIPUpdatesLocked(selector api.FQDNSelector)
}

//
// CachedSelector implementation (== Public API)
//
// No locking needed.
//

// UpdateResult is a bitfield that indicates what parts of the policy engines
// need to update in order to implement a policy
type UpdateResult uint32

const (
	// UpdateResultUpdatePolicyMaps indicates the caller should call EndpointManager.UpdatePolicyMaps()
	UpdateResultUpdatePolicyMaps = UpdateResult(1) << iota

	// UpdateResultIdentitiesNeeded indicates the caller should wait for a complete ipcache label injection,
	// as the selector is missing identities
	UpdateResultIdentitiesNeeded

	UpdateResultUnchanged = UpdateResult(0)
)

// UpdateFQDNSelector updates the mapping of fqdnKey (the FQDNSelector from a
// policy rule as a string) to to the provided list of IPs.
//
// If the supplied IPs are already known to the SelectorCache (i.e. they already)
// have identities allocated for them), the selector's cachedSelections changes, and
// users are notified asynchronously. Caller must then call Wait() on the supplied
// sync.WaitGroup before triggering any policy updates via UpdatePolicyMaps().
// Policy updates may need Endpoint locks, so this Wait() can deadlock if the caller
// is holding any endpoint locks. When this is the case, the returned UpdateResult has
// the UpdateResultUpdatePolicyMaps bit set.
//
// In the case where identities are not found for all supplied IPs, the returned
// result has the IdentitiesNeeded bit set to signify that an ipcache update is needed.
//
// The caller must always ensure that all selected IP addresses are known to the ipcache.
//
// Returns an UpdateResult that indicates if the caller should call UpdatePolicyMaps() and/or
// wait for ipcache UpsertMetadata() to finish.
func (sc *SelectorCache) UpdateFQDNSelector(fqdnSelec api.FQDNSelector, ips []netip.Addr, wg *sync.WaitGroup) UpdateResult {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	return sc.updateFQDNSelector(fqdnSelec, ips, wg)
}

func (sc *SelectorCache) updateFQDNSelector(fqdnSelec api.FQDNSelector, ips []netip.Addr, wg *sync.WaitGroup) UpdateResult {
	key := fqdnSelec.String()

	idSelector, exists := sc.selectors[key]
	if !exists || idSelector == nil {
		log.WithField(logfields.Selector, fqdnSelec.String()).Error("UpdateFQDNSelector of selector not registered in SelectorCache!")
	}

	fqdnSelect, ok := idSelector.source.(*fqdnSelector)
	if !ok {
		log.Error("UpdateFQDNSelector for non-FQDN selector!")
		return UpdateResultUnchanged
	}

	// update wantLabels, then determine set of added and removed identities
	fqdnSelect.setSelectorIPs(ips) // this updates wantLabels

	// Note that 'added' and 'deleted' are guaranteed to be
	// disjoint, as one of them is left as nil, or an identity
	// being in 'identities' is a precondition for an
	// identity to be appended to 'added', while the inverse is
	// true for 'deleted'.
	var added, deleted []identity.NumericIdentity

	// Delete any non-matching entries from cachedSelections
	for nid := range idSelector.cachedSelections {
		identity := sc.idCache[nid]
		if !idSelector.source.matches(identity) {
			deleted = append(deleted, nid)
			delete(idSelector.cachedSelections, nid)
		}
	}

	// Scan the cached set of IDs to determine any new matchers
	for nid, identity := range sc.idCache {
		if idSelector.source.matches(identity) {
			if _, exists := idSelector.cachedSelections[nid]; !exists {
				added = append(added, nid)
				idSelector.cachedSelections[nid] = struct{}{}
			}
		}
	}

	// Result indicates whether or not the caller should call UpdatePolicyMaps
	// and / or wait for ipcache to finish.
	result := UpdateResultUnchanged

	// If we're missing identities, then the caller also needs to wait for ipcache to do a
	// allocation + injection round
	//
	// This assumes we should have a 1:1 mapping from label to IPs, which is currently the case.
	// If this changes, this conditional will be wrong.
	if len(idSelector.cachedSelections) != len(fqdnSelect.wantLabels) {
		result |= UpdateResultIdentitiesNeeded
	}

	idSelector.updateSelections()

	// If the set of selections has changed, then we need to push out an
	// incremental update. This will add an incremental change to all users,
	// and tell the caller that a call to UpdatePolicyMaps is required.
	if len(added)+len(deleted) > 0 {
		result |= UpdateResultUpdatePolicyMaps
		idSelector.notifyUsers(sc, added, deleted, wg) // disjoint sets, see the comment above
	}

	return result
}

// AddFQDNSelector adds the given api.FQDNSelector in to the selector cache. If
// an identical EndpointSelector has already been cached, the corresponding
// CachedSelector is returned, otherwise one is created and added to the cache.
func (sc *SelectorCache) AddFQDNSelector(user CachedSelectionUser, lbls labels.LabelArray, fqdnSelec api.FQDNSelector) (cachedSelector CachedSelector, added bool) {
	key := fqdnSelec.String()

	// Lock NameManager before the SelectorCache. Always.
	// This is because SelectorCache and NameManager have interleaving locks,
	// so we must always acquire the NameManager lock first
	sc.localIdentityNotifier.Lock()
	defer sc.localIdentityNotifier.Unlock()
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	// If the selector already exists, use it.
	idSel, exists := sc.selectors[key]
	if exists {
		return idSel, idSel.addUser(user)
	}

	source := &fqdnSelector{
		selector: fqdnSelec,
	}

	// Make the FQDN subsystem aware of this selector and fetch ips
	// that the FQDN subsystem is aware of.
	currentIPs := sc.localIdentityNotifier.RegisterForIPUpdatesLocked(source.selector)
	source.setSelectorIPs(currentIPs)

	return sc.addSelector(user, lbls, key, source)
}

func (sc *SelectorCache) addSelector(user CachedSelectionUser, lbls labels.LabelArray, key string, source selectorSource) (CachedSelector, bool) {
	idSel := &identitySelector{
		key:              key,
		users:            make(map[CachedSelectionUser]struct{}),
		cachedSelections: make(map[identity.NumericIdentity]struct{}),
		source:           source,
		metadataLbls:     lbls,
	}
	sc.selectors[key] = idSel

	// Scan the cached set of IDs to determine any new matchers
	for nid, identity := range sc.idCache {
		if idSel.source.matches(identity) {
			idSel.cachedSelections[nid] = struct{}{}
		}
	}

	// Note: No notifications are sent for the existing
	// identities. Caller must use GetSelections() to get the
	// current selections after adding a selector. This way the
	// behavior is the same between the two cases here (selector
	// is already cached, or is a new one).

	// Create the immutable slice representation of the selected
	// numeric identities
	idSel.updateSelections()

	return idSel, idSel.addUser(user)

}

// FindCachedIdentitySelector finds the given api.EndpointSelector in the
// selector cache, returning nil if one can not be found.
func (sc *SelectorCache) FindCachedIdentitySelector(selector api.EndpointSelector) CachedSelector {
	key := selector.CachedString()
	sc.mutex.Lock()
	idSel := sc.selectors[key]
	sc.mutex.Unlock()
	return idSel
}

// AddIdentitySelector adds the given api.EndpointSelector in to the
// selector cache. If an identical EndpointSelector has already been
// cached, the corresponding CachedSelector is returned, otherwise one
// is created and added to the cache.
func (sc *SelectorCache) AddIdentitySelector(user CachedSelectionUser, lbls labels.LabelArray, selector api.EndpointSelector) (cachedSelector CachedSelector, added bool) {
	// The key returned here may be different for equivalent
	// labelselectors, if the selector's requirements are stored
	// in different orders. When this happens we'll be tracking
	// essentially two copies of the same selector.
	key := selector.CachedString()
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	idSel, exists := sc.selectors[key]
	if exists {
		return idSel, idSel.addUser(user)
	}

	// Selectors are never modified once a rule is placed in the policy repository,
	// so no need to deep copy.
	source := &labelIdentitySelector{
		selector: selector,
	}
	// check is selector has a namespace match or requirement
	if namespaces, ok := selector.GetMatch(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel); ok {
		source.namespaces = namespaces
	}

	return sc.addSelector(user, lbls, key, source)
}

// lock must be held
func (sc *SelectorCache) removeSelectorLocked(selector CachedSelector, user CachedSelectionUser) {
	key := selector.String()
	sel, exists := sc.selectors[key]
	if exists {
		if sel.removeUser(user) {
			sel.source.remove(sc.localIdentityNotifier)
			delete(sc.selectors, key)
		}
	}
}

// RemoveSelector removes CachedSelector for the user.
func (sc *SelectorCache) RemoveSelector(selector CachedSelector, user CachedSelectionUser) {
	sc.localIdentityNotifier.Lock()
	sc.mutex.Lock()
	sc.removeSelectorLocked(selector, user)
	sc.mutex.Unlock()
	sc.localIdentityNotifier.Unlock()

}

// RemoveSelectors removes CachedSelectorSlice for the user.
func (sc *SelectorCache) RemoveSelectors(selectors CachedSelectorSlice, user CachedSelectionUser) {
	sc.localIdentityNotifier.Lock()
	sc.mutex.Lock()
	for _, selector := range selectors {
		sc.removeSelectorLocked(selector, user)
	}
	sc.mutex.Unlock()
	sc.localIdentityNotifier.Unlock()
}

// ChangeUser changes the CachedSelectionUser that gets updates on the
// updates on the cached selector.
func (sc *SelectorCache) ChangeUser(selector CachedSelector, from, to CachedSelectionUser) {
	key := selector.String()
	sc.mutex.Lock()
	idSel, exists := sc.selectors[key]
	if exists {
		// Add before remove so that the count does not dip to zero in between,
		// as this causes FQDN unregistration (if applicable).
		idSel.addUser(to)
		// ignoring the return value as we have just added a user above
		idSel.removeUser(from)
	}
	sc.mutex.Unlock()
}

// UpdateIdentities propagates identity updates to selectors
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
//
// Caller should Wait() on the returned sync.WaitGroup before triggering any
// policy updates. Policy updates may need Endpoint locks, so this Wait() can
// deadlock if the caller is holding any endpoint locks.
func (sc *SelectorCache) UpdateIdentities(added, deleted cache.IdentityCache, wg *sync.WaitGroup) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	// Update idCache so that newly added selectors get
	// prepopulated with all matching numeric identities.
	for numericID := range deleted {
		if old, exists := sc.idCache[numericID]; exists {
			log.WithFields(logrus.Fields{
				logfields.Identity: numericID,
				logfields.Labels:   old.lbls,
			}).Debug("UpdateIdentities: Deleting identity")
			delete(sc.idCache, numericID)
		} else {
			log.WithFields(logrus.Fields{
				logfields.Identity: numericID,
			}).Warning("UpdateIdentities: Skipping Delete of a non-existing identity")
			delete(deleted, numericID)
		}
	}
	for numericID, lbls := range added {
		if old, exists := sc.idCache[numericID]; exists {
			// Skip if no change. Not skipping if label
			// order is different, but identity labels are
			// sorted for the kv-store, so there should
			// not be too many false negatives.
			if lbls.Equals(old.lbls) {
				log.WithFields(logrus.Fields{
					logfields.Identity: numericID,
				}).Debug("UpdateIdentities: Skipping add of an existing identical identity")
				delete(added, numericID)
				continue
			}
			scopedLog := log.WithFields(logrus.Fields{
				logfields.Identity:         numericID,
				logfields.Labels:           old.lbls,
				logfields.Labels + "(new)": lbls},
			)
			msg := "UpdateIdentities: Updating an existing identity"
			// Warn if any other ID has their labels change, besides local
			// host. The local host can have its labels change at runtime if
			// the kube-apiserver is running on the local host, see
			// ipcache.TriggerLabelInjection().
			if numericID == identity.ReservedIdentityHost {
				scopedLog.Debug(msg)
			} else {
				scopedLog.Warning(msg)
			}
		} else {
			log.WithFields(logrus.Fields{
				logfields.Identity: numericID,
				logfields.Labels:   lbls,
			}).Debug("UpdateIdentities: Adding a new identity")
		}
		sc.idCache[numericID] = newIdentity(numericID, lbls)
	}

	if len(deleted)+len(added) > 0 {
		// Iterate through all locally used identity selectors and
		// update the cached numeric identities as required.
		for _, idSel := range sc.selectors {
			var adds, dels []identity.NumericIdentity
			for numericID := range deleted {
				if _, exists := idSel.cachedSelections[numericID]; exists {
					dels = append(dels, numericID)
					delete(idSel.cachedSelections, numericID)
				}
			}
			for numericID := range added {
				if _, exists := idSel.cachedSelections[numericID]; !exists {
					if idSel.source.matches(sc.idCache[numericID]) {
						adds = append(adds, numericID)
						idSel.cachedSelections[numericID] = struct{}{}
					}
				}
			}
			if len(dels)+len(adds) > 0 {
				idSel.updateSelections()
				idSel.notifyUsers(sc, adds, dels, wg)
			}
		}
	}
}

// GetNetsLocked returns the most specific CIDR for an identity. For the "World" identity
// it returns both IPv4 and IPv6.
func (sc *SelectorCache) GetNetsLocked(id identity.NumericIdentity) []*net.IPNet {
	ident, ok := sc.idCache[id]
	if !ok {
		return nil
	}
	if !ident.computed {
		log.WithFields(logrus.Fields{
			logfields.Identity: id,
			logfields.Labels:   ident.lbls,
		}).Warning("GetNetsLocked: Identity with missing nets!")
	}
	return ident.nets
}
