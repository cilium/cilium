// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"iter"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
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

func (c *scIdentityCache) Len() int {
	return len(c.ids)
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

func (c *scIdentityCache) selections(sel *identitySelector) iter.Seq[identity.NumericIdentity] {
	return func(yield func(id identity.NumericIdentity) bool) {
		namespaces := sel.source.SelectedNamespaces()
		if len(namespaces) > 0 {
			// iterate identities in selected namespaces
			for _, ns := range namespaces {
				for id := range c.byNamespace[ns] {
					if sel.source.Matches(id.lbls) {
						if !yield(id.NID) {
							return
						}
					}
				}
			}
		} else {
			// no namespaces selected, iterate through all identities
			for nid, id := range c.ids {
				if sel.source.Matches(id.lbls) {
					if !yield(nid) {
						return
					}
				}
			}
		}
	}
}

type selectorMap struct {
	// map key is the string representation of the selector being cached.
	selectors map[string]*identitySelector

	// selectorsByNamespace indexes selectors by namespace for faster updates
	selectorsByNamespace map[string]map[*identitySelector]struct{}
}

func selectorMapInitializer() selectorMap {
	return selectorMap{
		selectors:            make(map[string]*identitySelector),
		selectorsByNamespace: make(map[string]map[*identitySelector]struct{}),
	}
}

func (m selectorMap) Len() int {
	return len(m.selectors)
}

func (m selectorMap) Empty() bool {
	return m.Len() == 0
}

func (m *selectorMap) All() iter.Seq2[string, *identitySelector] {
	return func(yield func(string, *identitySelector) bool) {
		for key, sel := range m.selectors {
			if !yield(key, sel) {
				return
			}
		}
	}
}

func (m *selectorMap) ByNamespace(ns string) iter.Seq[*identitySelector] {
	return func(yield func(*identitySelector) bool) {
		for sel := range m.selectorsByNamespace[ns] {
			if !yield(sel) {
				return
			}
		}
	}
}

func (m *selectorMap) Get(key string) (*identitySelector, bool) {
	sel, exists := m.selectors[key]
	return sel, exists
}

func (m *selectorMap) Set(key string, sel *identitySelector) {
	m.selectors[key] = sel

	namespaces := sel.source.SelectedNamespaces()
	if len(namespaces) == 0 {
		// use empty namespace string for selectors without namespace requirements
		namespaces = []string{""}
	}
	for _, ns := range namespaces {
		idx, exists := m.selectorsByNamespace[ns]
		if !exists {
			idx = make(map[*identitySelector]struct{})
			m.selectorsByNamespace[ns] = idx
		}
		idx[sel] = struct{}{}
	}
}

func (m *selectorMap) Delete(sel *identitySelector) {
	namespaces := sel.source.SelectedNamespaces()
	if len(namespaces) == 0 {
		// use empty namespace string for selectors without namespace
		// requirements
		namespaces = []string{""}
	}
	for _, ns := range namespaces {
		idx, exists := m.selectorsByNamespace[ns]
		if exists {
			delete(idx, sel)
			if len(idx) == 0 {
				delete(m.selectorsByNamespace, ns)
			}
		}
	}

	delete(m.selectors, sel.key)
}

// userNotification stores the information needed to call
// IdentitySelectionUpdated callbacks to notify users of selector's
// identity changes. These are queued to be able to call the callbacks
// in FIFO order while not holding any locks.
type userNotification struct {
	user     CachedSelectionUser
	selector CachedSelector   // nil for a sync notification
	txn      SelectorSnapshot // empty for non-sync notifications
	added    []identity.NumericIdentity
	deleted  []identity.NumericIdentity
	wg       *sync.WaitGroup
}

// SelectorCache caches identities, identity selectors, and the
// subsets of identities each selector selects.
type SelectorCache struct {
	logger *slog.Logger

	// readTxn for getting the current selections without taking any locks
	// The stored pointer is never nil after initialization.
	readTxn atomic.Pointer[SelectorSnapshot]

	mutex lock.RWMutex

	// revision is the revision number of selections, bumped on each commit.
	revision types.SelectorRevision

	// readableSelections holds the selections as of the last commit from writeableSelections.
	readableSelections types.SelectionsMap

	// writeableSelections is updated by each operation that may change the selections of a
	// selector (adding/removing selectors/identities) and is always kept open and committed on
	// request. Updates from all concurrent callers are pooled to the same write transaction
	// until Commit() is called.
	// There may be no other write transactions on 'selections'.
	writeableSelections types.SelectorWriteTxn

	// idCache contains all known identities as informed by the
	// kv-store and the local identity facility via our
	// UpdateIdentities() function.
	idCache scIdentityCache

	// selectorMap is the set of all cached selectors
	selectors selectorMap

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

	// userHandlerDone is initialized only in tests to allow termination of the handler
	userHandlerDone chan struct{}
}

// GetReadTxn returns a read-only state of the current selectors in the selector cache.
// The returned SelectorReadTxn should be Close()d as soon as possible to limit memory use.
func (sc *SelectorCache) GetSelectorSnapshot() SelectorSnapshot {
	return *sc.readTxn.Load()
}

// WithRLock calls the given function with the selector cache locked for reading, so that the caller
// may get ready for getting incremental updates (by registering as a user) that are possible right
// after the lock is released.  This should only be used with trivial functions that can not lock or
// sleep.
func (sc *SelectorCache) WithRLock(f func(sc *SelectorCache)) {
	// Lock synchronizes with UpdateIdentities() so that we do not use a stale version
	// that may already have received partial incremental updates.
	// Incremental updates are delivered asynchronously, so so the caller may still receive
	// updates for older versions. These should be filtered out.
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	f(sc)
}

// GetModel returns the API model of the SelectorCache.
func (sc *SelectorCache) GetModel() models.SelectorCache {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	selCacheMdl := make(models.SelectorCache, 0, sc.selectors.Len())

	// Get handle to the current version. Any concurrent updates will not be visible in the
	// returned model.
	version := sc.GetSelectorSnapshot()

	// iterating selectors requires read lock
	for key, sel := range sc.selectors.All() {
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

	version := sc.GetSelectorSnapshot()

	// iterating selectors requires read lock
	for _, sel := range sc.selectors.All() {
		if !sel.MaySelectPeers() {
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
	result.selectors = sc.selectors.Len()
	result.identities = sc.idCache.Len()

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
			// Allow testing code to stop the handler by sending a zero notification.
			if n.user == nil && sc.userHandlerDone != nil {
				close(sc.userHandlerDone)
				return
			}

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

func (sc *SelectorCache) queueNotifiedUsersCommit(txn SelectorSnapshot, wg *sync.WaitGroup) {
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
		logger:    logger,
		idCache:   newScIdentityCache(ids),
		selectors: selectorMapInitializer(),
	}
	sc.userCond = sync.NewCond(&sc.userMutex)
	sc.writeableSelections = sc.readableSelections.Txn()
	readTxn := types.GetSelectorSnapshot(sc.readableSelections, sc.revision)
	sc.readTxn.Store(&readTxn)
	return sc
}

func (sc *SelectorCache) RegisterMetrics() {
	if err := metrics.Register(newSelectorCacheMetrics(sc)); err != nil {
		sc.logger.Warn("Selector cache metrics registration failed. No metrics will be reported.", logfields.Error, err)
	}

	if err := metrics.Register(selectorCacheOperationDuration); err != nil {
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
	RegisterFQDNSelector(selector api.FQDNSelector) (ipcacheRevision uint64)

	// UnregisterFQDNSelector removes this FQDNSelector from the set of
	// IPs which are being tracked by the identityNotifier. The result
	// of this is that an IP may be evicted from IPCache if it is no longer
	// selected by any other FQDN selector.
	// This occurs when there are no more users of a given FQDNSelector for the
	// SelectorCache.
	UnregisterFQDNSelector(selector api.FQDNSelector) (ipcacheRevision uint64)
}

// commit applies all changes since the last commit to the selections and bumps the revision number
// by one. sc.writeTxn is reused for the next transaction. For this to work `sc.writeTxn` must have
// been initialized from `sc.selections.Txn()` and no other write transactions for the selections
// may exist.
//
// Lock must be held.
func (sc *SelectorCache) commit() SelectorSnapshot {
	sc.revision++
	sc.readableSelections = sc.writeableSelections.Commit()
	readTxn := types.GetSelectorSnapshot(sc.readableSelections, sc.revision)
	sc.readTxn.Store(&readTxn)
	return readTxn
}

// Commit makes the selections of new selectors added via AddSelectors visible via
// CachedSelector.GetSelections() and CachedSelector.GetSelectionsAt().
func (sc *SelectorCache) Commit() {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	sc.commit()
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
func (sc *SelectorCache) AddSelectorsTxn(user CachedSelectionUser, lbls stringLabels, selectors ...Selector) (CachedSelectorSlice, bool) {
	if selectsAll(selectors...) {
		selectors = []Selector{types.WildcardSelector}
	}

	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	return sc.addSelectorsTxn(user, lbls, selectors...)
}

// AddSelectors adds Selectors in to the selector cache, and returns the corresponding slice of
// cached selectors.
// Selections of new selectors are visible to readers right after this call.
func (sc *SelectorCache) AddSelectors(user CachedSelectionUser, lbls stringLabels, selectors ...Selector) (CachedSelectorSlice, bool) {
	if selectsAll(selectors...) {
		selectors = []Selector{types.WildcardSelector}
	}

	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	defer sc.commit()
	return sc.addSelectorsTxn(user, lbls, selectors...)
}

func (sc *SelectorCache) addSelectorsTxn(user CachedSelectionUser, lbls stringLabels, selectors ...Selector) (CachedSelectorSlice, bool) {
	css := make(CachedSelectorSlice, len(selectors))

	added := false
	for i, selector := range selectors {
		// Check if the selector has already been cached
		operationStart := time.Now()
		key := selector.Key()
		sel, exists := sc.selectors.Get(key)
		if !exists {
			// add the selector to the selector cache
			sel = sc.addSelectorLocked(lbls, key, selector)
		}

		if sel.addUser(user, sc.localIdentityNotifier) {
			added = true
		}
		css[i] = sel

		if !exists {
			selectorCacheOperationDuration.WithLabelValues(types.LabelValueSCOperationAddSelector, types.LabelValueSCOperation, types.LabelValueSCTypePeer).Observe(time.Since(operationStart).Seconds())
		}

	}
	return css, added
}

// must hold lock for writing
func (sc *SelectorCache) addSelectorLocked(lbls stringLabels, key string, source Selector) *identitySelector {
	sel := newIdentitySelector(sc, key, source, lbls)

	sc.selectors.Set(key, sel)

	// Scan the cached set of IDs to determine any new matchers
	for nid := range sc.idCache.selections(sel) {
		sel.cachedSelections[nid] = struct{}{}
	}

	// Note: No notifications are sent for the existing
	// identities. Caller must use GetSelections() to get the
	// current selections after adding a selector. This way the
	// behavior is the same between the two cases here (selector
	// is already cached, or is a new one).

	// Create the immutable slice representation of the selected
	// numeric identities
	sel.updateSelections()

	return sel
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
	sel, exists := sc.selectors.Get(key)
	if !exists {
		sel = sc.addSelectorLocked(lbls, key, types.NewLabelSelector(es))
		sc.commit()
	}
	return sel, sel.addUser(user, sc.localIdentityNotifier)
}

// lock must be held
func (sc *SelectorCache) removeSelectorLocked(selector CachedSelector, user CachedSelectionUser) {
	start := time.Now()
	key := selector.String()
	sel, exists := sc.selectors.Get(key)
	if exists && sel.removeUser(user, sc.localIdentityNotifier) {
		sc.selectors.Delete(sel)
		sel.updateSelections()
		selectorCacheOperationDuration.WithLabelValues(types.LabelValueSCOperationRemoveSelector, types.LabelValueSCOperation, types.LabelValueSCTypePeer).Observe(time.Since(start).Seconds())
	}
}

// RemoveSelector removes CachedSelector for the user.
func (sc *SelectorCache) RemoveSelector(selector CachedSelector, user CachedSelectionUser) {
	sc.mutex.Lock()
	sc.removeSelectorLocked(selector, user)
	sc.commit()
	sc.mutex.Unlock()
}

// RemoveSelectors removes CachedSelectorSlice for the user.
func (sc *SelectorCache) RemoveSelectors(selectors CachedSelectorSlice, user CachedSelectionUser) {
	sc.mutex.Lock()
	for _, selector := range selectors {
		sc.removeSelectorLocked(selector, user)
	}
	sc.commit()
	sc.mutex.Unlock()
}

// ChangeUser changes the CachedSelectionUser that gets updates on the
// updates on the cached selector.
func (sc *SelectorCache) ChangeUser(selector CachedSelector, from, to CachedSelectionUser) {
	key := selector.String()
	sc.mutex.Lock()
	sel, exists := sc.selectors.Get(key)
	if exists {
		// Add before remove so that the count does not dip to zero in between,
		// as this causes FQDN unregistration (if applicable).
		sel.addUser(to, nil)
		// ignoring the return value as we have just added a user above
		sel.removeUser(from, nil)
	}
	sc.mutex.Unlock()
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

// updateSelector updates the selections of the given selector as follows:
// - remove deleted identities from the selections
// - add the added identity to the selections for each matching identity
// - notify users of any changes
// Returns:
// - updated as true if any changes were made
// - mutated as true if any identity was mutated
func (sc *SelectorCache) updateSelections(sel *identitySelector, added identity.NumericIdentitySlice, deleted identity.IdentityMap, wg *sync.WaitGroup) (updated, mutated bool) {
	var adds, dels []identity.NumericIdentity
	for numericID := range deleted {
		if _, exists := sel.cachedSelections[numericID]; exists {
			dels = append(dels, numericID)
			delete(sel.cachedSelections, numericID)
		}
	}
	for _, numericID := range added {
		identity, _ := sc.idCache.find(numericID)
		matches := sel.source.Matches(identity.lbls)
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
		sel.updateSelections()
		sel.notifyUsers(sc, adds, dels, wg)
	}
	return updated, mutated
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

	start := time.Now()
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	operationStart := time.Now()
	defer func() {
		selectorCacheOperationDuration.WithLabelValues(types.LabelValueSCOperationIdentityUpdates, types.LabelValueSCOperationLock, types.LabelValueSCTypePeer).Observe(operationStart.Sub(start).Seconds())
		selectorCacheOperationDuration.WithLabelValues(types.LabelValueSCOperationIdentityUpdates, types.LabelValueSCOperation, types.LabelValueSCTypePeer).Observe(time.Since(operationStart).Seconds())
	}()

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
			for sel := range sc.selectors.ByNamespace(ns) {
				u, m := sc.updateSelections(sel, nsAdded, deleted, wg)
				updated = updated || u
				mutated = mutated || m
			}
		}
	}

	if updated {
		readTxn := sc.commit()
		sc.queueNotifiedUsersCommit(readTxn, wg)
	}
	return mutated
}
