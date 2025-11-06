// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"iter"
	"log/slog"
	"runtime"
	"sync"
	"weak"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

var (
	podNamespaceLabel = labels.NewLabel(k8sConst.PodNamespaceLabel, "", labels.LabelSourceK8s)
)

// scIdentity is the information we need about a an identity that rules can select
type scIdentity struct {
	NID       identity.NumericIdentity
	lbls      labels.LabelArray
	namespace string // value of the namespace label, or ""
}

// scIdentityCache is a cache of Identities keyed by the numeric identity
type scIdentityCache struct {
	ids         map[identity.NumericIdentity]*scIdentity
	byNamespace map[string]map[*scIdentity]struct{}
}

func newScIdentityCache(ids identity.IdentityMap) scIdentityCache {
	idCache := scIdentityCache{
		ids:         make(map[identity.NumericIdentity]*scIdentity, len(ids)),
		byNamespace: make(map[string]map[*scIdentity]struct{}, len(ids)),
	}

	for nid, lbls := range ids {
		idCache.insert(nid, lbls)
	}

	return idCache
}

func (c *scIdentityCache) insert(nid identity.NumericIdentity, lbls labels.LabelArray) *scIdentity {
	namespace, _ := lbls.LookupLabel(&podNamespaceLabel)
	id := &scIdentity{
		NID:       nid,
		lbls:      lbls,
		namespace: namespace,
	}

	c.ids[nid] = id
	m := c.byNamespace[id.namespace]
	if m == nil {
		m = make(map[*scIdentity]struct{})
		c.byNamespace[id.namespace] = m
	}
	m[id] = struct{}{}

	return id
}

func (c *scIdentityCache) delete(nid identity.NumericIdentity) bool {
	id, exists := c.ids[nid]
	if exists {
		if m := c.byNamespace[id.namespace]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(c.byNamespace, id.namespace)
			}
		}
		delete(c.ids, nid)
	}
	return exists
}

func (c *scIdentityCache) find(nid identity.NumericIdentity) (*scIdentity, bool) {
	id := c.ids[nid]
	return id, id != nil
}

func (c *scIdentityCache) exists(nid identity.NumericIdentity) bool {
	id := c.ids[nid]
	return id != nil
}

func (c *scIdentityCache) selections(idSel *identitySelector) iter.Seq[identity.NumericIdentity] {
	return func(yield func(id identity.NumericIdentity) bool) {
		namespaces := idSel.source.SelectedNamespaces()
		if len(namespaces) > 0 {
			// iterate identities in selected namespaces
			for _, ns := range namespaces {
				for id := range c.byNamespace[ns] {
					if idSel.source.Matches(idSel.selectorCache.logger, id.lbls) {
						if !yield(id.NID) {
							return
						}
					}
				}
			}
		} else {
			// no namespaces selected, iterate through all identities
			for nid, id := range c.ids {
				if idSel.source.Matches(idSel.selectorCache.logger, id.lbls) {
					if !yield(nid) {
						return
					}
				}
			}
		}
	}
}

// userNotification stores the information needed to call
// IdentitySelectionUpdated callbacks to notify users of selector's
// identity changes. These are queued to be able to call the callbacks
// in FIFO order while not holding any locks.
type userNotification struct {
	user     CachedSelectionUser
	selector CachedSelector  // nil for a sync notification
	txn      SelectorReadTxn // empty for non-sync notifications
	added    []identity.NumericIdentity
	deleted  []identity.NumericIdentity
	wg       *sync.WaitGroup
}

// SelectorCache caches identities, identity selectors, and the
// subsets of identities each selector selects.
type SelectorCache struct {
	logger *slog.Logger

	mutex lock.RWMutex

	selections types.SelectionsMap
	revision   types.SelectorRevision

	// writeTxn is always kept open and committed on request. Changes from all concurrent
	// callers will be be pooled to the same write transaction until Commit() is called.
	writeTxn types.SelectorWriteTxn

	// idCache contains all known identities as informed by the
	// kv-store and the local identity facility via our
	// UpdateIdentities() function.
	idCache scIdentityCache

	// map key is the string representation of the selector being cached.
	selectors map[string]weak.Pointer[identitySelector]

	// selectorsByNamespace indexes selectors by namespace for faster updates
	selectorsByNamespace map[string]map[weak.Pointer[identitySelector]]struct{}

	localIdentityNotifier identityNotifier

	// userCond is a condition variable for receiving signals
	// about addition of new elements in userNotes
	userCond *sync.Cond
	// userMutex protects userNotes and is linked to userCond
	userMutex lock.Mutex
	// userNotes holds a FIFO list of user notifications to be made
	userNotes []userNotification
	// notifiedUsers is a set of all notified users
	notifiedUsers map[CachedSelectionUser]struct{}

	// used to lazily start the handler for user notifications.
	startNotificationsHandlerOnce sync.Once
}

func (sc *SelectorCache) getReadTxn() SelectorReadTxn {
	return types.GetSelectorReadTxn(sc.selections, sc.revision)
}

func (sc *SelectorCache) GetReadTxn() SelectorReadTxn {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	return sc.getReadTxn()
}

// GetReadTxnFunc calls the given function with a statedb.ReadTxn for the current version of
// SelectorCache selections while selector cache is locked for writing, so that the caller may get
// ready for getting incremental updates that are possible right after the lock is released.
// This should only be used with trivial functions that can not lock or sleep.  Use the plain
// 'GetReadTxn' whenever possible, as it does not lock the selector cache.  SelectorReadTxn passed
// to 'f' must be closed with Close().
func (sc *SelectorCache) GetReadTxnFunc(f func(SelectorReadTxn)) {
	// Lock synchronizes with UpdateIdentities() so that we do not use a stale version
	// that may already have received partial incremental updates.
	// Incremental updates are delivered asynchronously, so so the caller may still receive
	// updates for older versions. These should be filtered out.
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	f(sc.getReadTxn())
}

func (sc *SelectorCache) validSelectors() iter.Seq2[string, *identitySelector] {
	return func(yield func(string, *identitySelector) bool) {
		for key, wp := range sc.selectors {
			sel := wp.Value()
			if sel != nil && !yield(key, sel) {
				return
			}
		}
	}
}

// GetModel returns the API model of the SelectorCache.
func (sc *SelectorCache) GetModel() models.SelectorCache {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	selCacheMdl := make(models.SelectorCache, 0, len(sc.selectors))

	// Get handle to the current version. Any concurrent updates will not be visible in the
	// returned model.
	version := sc.getReadTxn()

	for key, sel := range sc.validSelectors() {
		selections := sel.GetSelectionsAt(version)
		ids := make([]int64, 0, len(selections))
		for i := range selections {
			ids = append(ids, int64(selections[i]))
		}
		selMdl := &models.SelectorIdentityMapping{
			Selector:   key,
			Identities: ids,
			Users:      int64(sel.numUsers()),
			Labels:     labelArrayToModel(sel.GetMetadataLabels()),
		}
		selCacheMdl = append(selCacheMdl, selMdl)
	}

	return selCacheMdl
}

func (sc *SelectorCache) Stats() selectorStats {
	result := newSelectorStats()

	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	version := sc.getReadTxn()

	for _, sel := range sc.validSelectors() {
		if !sel.hasUsers() {
			// Peer selectors impact policymap cardinality, but
			// subject selectors do not. Do not count cardinality
			// if the selector is only used for policy subjects.
			continue
		}

		selections := sel.GetSelectionsAt(version)
		class := sel.source.MetricsClass()
		if result.maxCardinalityByClass[class] < len(selections) {
			result.maxCardinalityByClass[class] = len(selections)
		}
	}

	return result
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
			if n.selector == nil {
				n.user.IdentitySelectionCommit(sc.logger, n.txn)
			} else {
				n.user.IdentitySelectionUpdated(sc.logger, n.selector, n.added, n.deleted)
			}
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
	if sc.notifiedUsers == nil {
		sc.notifiedUsers = make(map[CachedSelectionUser]struct{})
	}
	sc.notifiedUsers[user] = struct{}{}
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

func (sc *SelectorCache) queueNotifiedUsersCommit(txn SelectorReadTxn, wg *sync.WaitGroup) {
	sc.userMutex.Lock()
	for user := range sc.notifiedUsers {
		wg.Add(1)

		// sync notification has a nil selector
		sc.userNotes = append(sc.userNotes, userNotification{
			user: user,
			txn:  txn,
			wg:   wg,
		})
	}
	sc.notifiedUsers = nil
	sc.userMutex.Unlock()
	sc.userCond.Signal()
}

// NewSelectorCache creates a new SelectorCache with the given identities.
func NewSelectorCache(logger *slog.Logger, ids identity.IdentityMap) *SelectorCache {
	sc := &SelectorCache{
		logger:               logger,
		idCache:              newScIdentityCache(ids),
		selectors:            make(map[string]weak.Pointer[identitySelector]),
		selectorsByNamespace: make(map[string]map[weak.Pointer[identitySelector]]struct{}),
	}
	sc.userCond = sync.NewCond(&sc.userMutex)
	sc.writeTxn = sc.selections.Txn()
	return sc
}

func (sc *SelectorCache) RegisterMetrics() {
	if err := metrics.Register(newSelectorCacheMetrics(sc)); err != nil {
		sc.logger.Warn("Selector cache metrics registration failed. No metrics will be reported.", logfields.Error, err)
	}
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
	// wildcardSelectorKey is used to compare if a key is for a wildcard
	wildcardSelectorKey = api.WildcardEndpointSelector.LabelSelector.String()
	// noneSelectorKey is used to compare if a key is for "reserved:none"
	noneSelectorKey = api.EndpointSelectorNone.LabelSelector.String()
)

// identityNotifier provides a means for other subsystems to be made aware of a
// given FQDNSelector (currently pkg/fqdn) so that said subsystems can notify
// the IPCache about IPs which correspond to said FQDNSelector.
// This is necessary as there is nothing intrinsic about an IP that says that
// it corresponds to a given FQDNSelector; this relationship is contained only
// via DNS responses, which are handled externally.
type identityNotifier interface {
	// RegisterFQDNSelector exposes this FQDNSelector so that the identity labels
	// of IPs contained in a DNS response that matches said selector can be
	// associated with that selector.
	RegisterFQDNSelector(selector api.FQDNSelector)

	// UnregisterFQDNSelector removes this FQDNSelector from the set of
	// IPs which are being tracked by the identityNotifier. The result
	// of this is that an IP may be evicted from IPCache if it is no longer
	// selected by any other FQDN selector.
	// This occurs when there are no more users of a given FQDNSelector for the
	// SelectorCache.
	UnregisterFQDNSelector(selector api.FQDNSelector)
}

func (sc *SelectorCache) commit() {
	sc.revision++
	sc.selections = sc.writeTxn.Commit()
	// immediately reopen a new transaction for further changes
	sc.writeTxn = sc.selections.Txn()
}

func (sc *SelectorCache) Commit() {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	sc.commit()
}

// AddSelectorUser registers 'user' for incremental updates for each CachedSelector in 'csMap'.
func AddSelectorUser[T any](sc *SelectorCache, user CachedSelectionUser, csMap map[CachedSelector]T) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	for cs := range csMap {
		cs.(*identitySelector).addUser(user, sc.localIdentityNotifier)
	}
}

// RemoveUser removes the user from the given cached selector.
func RemoveSelectorUser[T any](sc *SelectorCache, user CachedSelectionUser, csMap map[CachedSelector]T) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	for cs := range csMap {
		cs.(*identitySelector).removeUser(user, sc.localIdentityNotifier)
	}
}

// AddUser registers 'user' for incremental updates for each CachedSelector in 'css'.
func (sc *SelectorCache) AddUser(user CachedSelectionUser, css ...CachedSelector) bool {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	added := false
	for _, cs := range css {
		if sel, ok := cs.(*identitySelector); ok {
			if sel.addUser(user, sc.localIdentityNotifier) {
				added = true
			}
		}
	}
	return added
}

// RemoveUser removes the user from the given cached selector.
func (sc *SelectorCache) RemoveUser(user CachedSelectionUser, selectors ...types.CachedSelector) {
	sc.mutex.Lock()
	for _, selector := range selectors {
		selector.(*identitySelector).removeUser(user, sc.localIdentityNotifier)
	}
	sc.mutex.Unlock()
}

// userCount returns the current user count of the given cached selector
// Useful for testing that users are removed properly.
func (sc *SelectorCache) userCount(cs CachedSelector) int {
	if sel, ok := cs.(*identitySelector); ok {
		sc.mutex.RLock()
		defer sc.mutex.RUnlock()
		return sel.numUsers()
	}
	return 0
}

func selectsAll(selectors ...Selector) bool {
	if len(selectors) == 0 {
		return true
	}
	for idx := range selectors {
		if selectors[idx].IsWildcard() {
			return true
		}
	}
	return false
}

// AddSelectorsTxn adds Selectors in to the selector cache, and returns the corresponding
// slice of cached selectors.
// Commit() must be called aftewards to make the selections of new selectors observable by readers.
func (sc *SelectorCache) AddSelectorsTxn(lbls stringLabels, selectors ...Selector) CachedSelectorSlice {
	if selectsAll(selectors...) {
		selectors = []Selector{types.WildcardSelector}
	}

	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	return sc.addSelectorsTxn(lbls, selectors...)
}

// AddSelectors adds Selectors in to the selector cache, and returns the corresponding slice of
// cached selectors.
// Selections of new selectors are visible to readers right after this call.
func (sc *SelectorCache) AddSelectors(lbls stringLabels, selectors ...Selector) CachedSelectorSlice {
	if selectsAll(selectors...) {
		selectors = []Selector{types.WildcardSelector}
	}

	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	defer sc.commit()
	return sc.addSelectorsTxn(lbls, selectors...)
}

func (sc *SelectorCache) addSelectorsTxn(lbls stringLabels, selectors ...Selector) CachedSelectorSlice {
	css := make(CachedSelectorSlice, len(selectors))

	for i, selector := range selectors {
		// Check if the selector has already been cached
		key := selector.Key()
		wp, exists := sc.selectors[key]
		var sel *identitySelector
		if exists {
			sel = wp.Value()
		}
		if sel == nil {
			// add the selector to the selector cache
			sel = sc.addSelectorLocked(sc.writeTxn, lbls, key, selector)
		}

		css[i] = sel
	}
	return css
}

// finalizer is set to eventually remove stale weak pointers from the selectors map.  Stale weak
// pointers are removed from the namespace index when scanning for updates in
// UpdateIdentities(). Similar clean-up while scanning can not be done for the main selectors map as
// there is no need to iterate over it otherwise.
// This could probably be done more efficiently via a timer job periodically.
func (sc *SelectorCache) finalizer(sel *identitySelector) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if len(sel.users) > 0 {
		sc.logger.Warn(
			"selector GC'd with registered users",
			logfields.User, sel.users,
		)
	}

	// Must check that the selector has not been cached again while GC took the time to run this
	// finalizer! We remove the weak pointer only if it cant be turned into a strong one.
	wp, exists := sc.selectors[sel.key]
	if exists && wp.Value() == nil {
		delete(sc.selectors, sel.key)
	}
}

// must hold lock for writing
func (sc *SelectorCache) addSelectorLocked(txn SelectorTxn, lbls stringLabels, key string, source Selector) *identitySelector {
	idSel := newIdentitySelector(sc, key, source, lbls)

	runtime.SetFinalizer(idSel, sc.finalizer)

	wp := weak.Make(idSel)
	sc.selectors[key] = wp

	namespaces := source.SelectedNamespaces()
	if len(namespaces) == 0 {
		// use empty namespace string for selectors without namespace requirements
		namespaces = []string{""}
	}
	for _, ns := range namespaces {
		idx, exists := sc.selectorsByNamespace[ns]
		if !exists {
			idx = make(map[weak.Pointer[identitySelector]]struct{})
			sc.selectorsByNamespace[ns] = idx
		}
		idx[wp] = struct{}{}
	}

	// Scan the cached set of IDs to determine any new matchers
	for nid := range sc.idCache.selections(idSel) {
		idSel.cachedSelections[nid] = struct{}{}
	}

	// Note: No notifications are sent for the existing
	// identities. Caller must use GetSelections() to get the
	// current selections after adding a selector. This way the
	// behavior is the same between the two cases here (selector
	// is already cached, or is a new one).

	// Create the immutable slice representation of the selected
	// numeric identities
	idSel.updateSelections(txn)

	return idSel
}

// AddIdentitySelectorForTest adds the given api.EndpointSelector in to the
// selector cache. If an identical EndpointSelector has already been
// cached, the corresponding CachedSelector is returned, otherwise one
// is created and added to the cache.
// NOTE: Only used for testing, but from multiple packages
func (sc *SelectorCache) AddIdentitySelectorForTest(user CachedSelectionUser, lbls stringLabels, es api.EndpointSelector) (cachedSelector CachedSelector, added bool) {
	// The key returned here may be different for equivalent
	// labelselectors, if the selector's requirements are stored
	// in different orders. When this happens we'll be tracking
	// essentially two copies of the same selector.
	key := es.CachedString()
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	wp, exists := sc.selectors[key]
	var sel *identitySelector
	if exists {
		sel = wp.Value()
	}
	if sel == nil {
		sel = sc.addSelectorLocked(sc.writeTxn, lbls, key, types.NewLabelSelector(es))
		sc.commit()
	}
	return sel, sel.addUser(user, sc.localIdentityNotifier)
}

// CanSkipUpdate returns true if a proposed update is already known to the SelectorCache
// and thus a no-op. Is used to de-dup an ID update stream, because identical updates
// may come from multiple sources.
func (sc *SelectorCache) CanSkipUpdate(added, deleted identity.IdentityMap) bool {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	for nid := range deleted {
		if sc.idCache.exists(nid) {
			return false
		}
	}

	for nid, lbls := range added {
		haslbls, exists := sc.idCache.find(nid)
		if !exists { // id not known to us: cannot skip
			return false
		}
		if !haslbls.lbls.Equals(lbls) {
			// labels are not equal: cannot skip
			return false
		}
	}
	return true
}

// UpdateIdentities propagates identity updates to selectors
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
//
// Caller should Wait() on the returned sync.WaitGroup before triggering any
// policy updates. Policy updates may need Endpoint locks, so this Wait() can
// deadlock if the caller is holding any endpoint locks.
//
// Incremental deletes of mutated identities are not sent to the users, as that could
// lead to deletion of policy map entries while other selectors may still select the mutated
// identity.
// In this case the return value is 'true' and the caller should trigger policy updates on all
// endpoints to remove the affected identity only from selectors that no longer select the mutated
// identity.
func (sc *SelectorCache) UpdateIdentities(added, deleted identity.IdentityMap, wg *sync.WaitGroup) (mutated bool) {
	// Map of namespaces to scan for updates with added identities in the map value. All
	// identities are matched against selectors that have no namespace requirements.
	namespaces := map[string]identity.NumericIdentitySlice{"": {}}

	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	nextRev := sc.revision + 1

	// Update idCache so that newly added selectors get
	// prepopulated with all matching numeric identities.
	for numericID := range deleted {
		if old, exists := sc.idCache.find(numericID); exists {
			sc.logger.Debug(
				"UpdateIdentities: Deleting identity",
				logfields.NewVersion, nextRev,
				logfields.Identity, numericID,
				logfields.Labels, old.lbls,
			)
			namespaces[old.namespace] = identity.NumericIdentitySlice{}
			sc.idCache.delete(numericID)
		} else {
			sc.logger.Warn(
				"UpdateIdentities: Skipping Delete of a non-existing identity",
				logfields.NewVersion, nextRev,
				logfields.Identity, numericID,
			)
			delete(deleted, numericID)
		}
	}
	for numericID, lbls := range added {
		if old, exists := sc.idCache.find(numericID); exists {
			// Skip if no change. Not skipping if label
			// order is different, but identity labels are
			// sorted for the kv-store, so there should
			// not be too many false negatives.
			if lbls.Equals(old.lbls) {
				sc.logger.Debug(
					"UpdateIdentities: Skipping add of an existing identical identity",
					logfields.NewVersion, nextRev,
					logfields.Identity, numericID,
				)
				delete(added, numericID)
				continue
			}
			msg := "UpdateIdentities: Updating an existing identity"
			// Warn if any other ID has their labels change, besides local
			// host. The local host can have its labels change at runtime if
			// the kube-apiserver is running on the local host, see
			// ipcache.TriggerLabelInjection().
			if numericID == identity.ReservedIdentityHost {
				sc.logger.Debug(msg,
					logfields.NewVersion, nextRev,
					logfields.Identity, numericID,
					logfields.Labels, old.lbls,
					logfields.LabelsNew, lbls,
				)
			} else {
				sc.logger.Warn(msg,
					logfields.NewVersion, nextRev,
					logfields.Identity, numericID,
					logfields.Labels, old.lbls,
					logfields.LabelsNew, lbls,
				)
			}
		} else {
			sc.logger.Debug(
				"UpdateIdentities: Adding a new identity",
				logfields.NewVersion, nextRev,
				logfields.Identity, numericID,
				logfields.Labels, lbls,
			)
		}
		id := sc.idCache.insert(numericID, lbls)

		namespaces[id.namespace] = append(namespaces[id.namespace], numericID)

		// namespaced identities are also checked against non-namespeced selectors
		if id.namespace != "" {
			namespaces[""] = append(namespaces[""], numericID)
		}
	}

	updated := false
	if len(deleted)+len(added) > 0 {
		for ns, nsAdded := range namespaces {
			// Iterate through all locally used identity selectors and
			// update the cached numeric identities as required.
			for wp := range sc.selectorsByNamespace[ns] {
				sel := wp.Value()
				if sel == nil {
					// clean up stale cached selectors as we go
					delete(sc.selectorsByNamespace[ns], wp)
					if len(sc.selectorsByNamespace[ns]) == 0 {
						delete(sc.selectorsByNamespace, ns)
					}
					continue
				}
				var adds, dels []identity.NumericIdentity
				for numericID := range deleted {
					if _, exists := sel.cachedSelections[numericID]; exists {
						dels = append(dels, numericID)
						delete(sel.cachedSelections, numericID)
					}
				}
				for _, numericID := range nsAdded {
					identity, _ := sc.idCache.find(numericID)
					matches := sel.source.Matches(sc.logger, identity.lbls)
					_, exists := sel.cachedSelections[numericID]
					if matches && !exists {
						adds = append(adds, numericID)
						sel.cachedSelections[numericID] = struct{}{}
					} else if !matches && exists {
						// Identity was mutated and no longer matches, the
						// identity is deleted from the cached selections,
						// but is not sent to users as a deletion. Instead,
						// we return 'mutated = true' telling the caller to
						// trigger forced policy updates on all endpoints to
						// recompute the policy as if the mutated identity
						// was never selected by the affected selector.
						mutated = true
						delete(sel.cachedSelections, numericID)
					}
				}
				if len(dels)+len(adds) > 0 {
					updated = true
					sel.updateSelections(sc.writeTxn)
					sel.notifyUsers(sc, adds, dels, wg)
				}
			}
		}
	}

	if updated {
		sc.commit()
		sc.queueNotifiedUsersCommit(sc.getReadTxn(), wg)
	}
	return mutated
}
