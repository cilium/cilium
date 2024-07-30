// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"
	"hash/fnv"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// NameManager maintains state DNS names, via FQDNSelector or exact match for
// polling, need to be tracked. It is the main structure which relates the FQDN
// subsystem to the policy subsystem for plumbing the relation between a DNS
// name and the corresponding IPs which have been returned via DNS lookups.
// When DNS updates are given to a NameManager it update cached selectors as
// required via UpdateSelectors.
// DNS information is cached, respecting TTL.
type NameManager struct {
	lock.RWMutex

	// config is a copy from when this instance was initialized.
	// It is read-only once set
	config Config

	// allSelectors contains all FQDNSelectors which are present in all policy. We
	// use these selectors to map selectors --> IPs.
	allSelectors map[api.FQDNSelector]*regexp.Regexp

	// cache is a private copy of the pointer from config.
	cache *DNSCache

	bootstrapCompleted bool

	// restoredPrefixes contains all prefixes for which we have restored the
	// IPCache metadata from previous Cilium v1.15 installation.
	// Cleared by CompleteBoostrap
	restoredPrefixes sets.Set[netip.Prefix]

	manager *controller.Manager

	// list of locks used as coordination points for name updates
	// see LockName() for details.
	nameLocks []*lock.Mutex
}

// GetModel returns the API model of the NameManager.
func (n *NameManager) GetModel() *models.NameManager {
	n.RWMutex.RLock()
	defer n.RWMutex.RUnlock()

	allSelectors := make([]*models.SelectorEntry, 0, len(n.allSelectors))
	for fqdnSel, regex := range n.allSelectors {
		pair := &models.SelectorEntry{
			SelectorString: fqdnSel.String(),
			RegexString:    regex.String(),
		}
		allSelectors = append(allSelectors, pair)
	}

	return &models.NameManager{
		FQDNPolicySelectors: allSelectors,
	}
}

var (
	DNSSourceLookup     = "lookup"
	DNSSourceConnection = "connection"
)

type NoEndpointIDMatch struct {
	ID string
}

func (e NoEndpointIDMatch) Error() string {
	return "unable to find target endpoint ID: " + e.ID
}

// GetDNSHistoryModel returns API models.DNSLookup copies of DNS data in each
// endpoint's DNSHistory. These are filtered by the specified matchers if
// they are non-empty.
//
// Note that this does *NOT* dump the NameManager's own global DNSCache.
//
// endpointID may be "" in order to get DNS history for all endpoints.
func (n *NameManager) GetDNSHistoryModel(endpointID string, prefixMatcher PrefixMatcherFunc, nameMatcher NameMatcherFunc, source string) (lookups []*models.DNSLookup, err error) {
	eps := n.config.GetEndpointsDNSInfo(endpointID)
	if eps == nil {
		return nil, &NoEndpointIDMatch{ID: endpointID}
	}
	for _, ep := range eps {
		lookupSourceEntries := []*models.DNSLookup{}
		connectionSourceEntries := []*models.DNSLookup{}
		for _, lookup := range ep.DNSHistory.Dump() {
			if !nameMatcher(lookup.Name) {
				continue
			}

			// The API model needs strings
			IPStrings := make([]string, 0, len(lookup.IPs))

			// only proceed if any IP matches the prefix selector
			anIPMatches := false
			for _, ip := range lookup.IPs {
				anIPMatches = anIPMatches || prefixMatcher(ip)
				IPStrings = append(IPStrings, ip.String())
			}
			if !anIPMatches {
				continue
			}

			lookupSourceEntries = append(lookupSourceEntries, &models.DNSLookup{
				Fqdn:           lookup.Name,
				Ips:            IPStrings,
				LookupTime:     strfmt.DateTime(lookup.LookupTime),
				TTL:            int64(lookup.TTL),
				ExpirationTime: strfmt.DateTime(lookup.ExpirationTime),
				EndpointID:     int64(ep.ID64),
				Source:         DNSSourceLookup,
			})
		}

		for _, delete := range ep.DNSZombies.DumpAlive(prefixMatcher) {
			for _, name := range delete.Names {
				if !nameMatcher(name) {
					continue
				}

				connectionSourceEntries = append(connectionSourceEntries, &models.DNSLookup{
					Fqdn:           name,
					Ips:            []string{delete.IP.String()},
					LookupTime:     strfmt.DateTime(delete.AliveAt),
					TTL:            0,
					ExpirationTime: strfmt.DateTime(ep.DNSZombies.nextCTGCUpdate),
					EndpointID:     int64(ep.ID64),
					Source:         DNSSourceConnection,
				})
			}
		}

		switch source {
		case DNSSourceLookup:
			lookups = append(lookups, lookupSourceEntries...)
		case DNSSourceConnection:
			lookups = append(lookups, connectionSourceEntries...)
		default:
			lookups = append(lookups, lookupSourceEntries...)
			lookups = append(lookups, connectionSourceEntries...)
		}
	}

	return lookups, nil
}

// RegisterFQDNSelector exposes this FQDNSelector so that the identity labels
// of IPs contained in a DNS response that matches said selector can be
// associated with that selector.
// This function also evaluates if any DNS names in the cache are matched by
// this new selector and updates the labels for those DNS names accordingly.
func (n *NameManager) RegisterFQDNSelector(selector api.FQDNSelector) {
	n.Lock()
	defer n.Unlock()

	_, exists := n.allSelectors[selector]
	if exists {
		log.WithField("fqdnSelector", selector).Warning("FQDNSelector was already registered for updates.")
	} else {
		// This error should never occur since the FQDNSelector has already been
		// validated, but account for it for good measure.
		regex, err := selector.ToRegex()
		if err != nil {
			log.WithError(err).WithField("fqdnSelector", selector).Error("FQDNSelector did not compile to valid regex")
			return
		}

		n.allSelectors[selector] = regex
		if metrics.FQDNSelectors.IsEnabled() {
			metrics.FQDNSelectors.Set(float64(len(n.allSelectors)))
		}
	}

	// The newly added FQDN selector could match DNS Names in the cache. If
	// that is the case, we want to update the IPCache metadata for all
	// associated IPs
	selectedNamesAndIPs := n.mapSelectorsToNamesLocked(selector)
	n.updateMetadata(deriveLabelsForNames(selectedNamesAndIPs, n.allSelectors))
}

// UnregisterFQDNSelector removes this FQDNSelector from the set of
// IPs which are being tracked by the identityNotifier. The result
// of this is that an IP may be evicted from IPCache if it is no longer
// selected by any other FQDN selector.
func (n *NameManager) UnregisterFQDNSelector(selector api.FQDNSelector) {
	n.Lock()
	defer n.Unlock()

	// Remove selector
	delete(n.allSelectors, selector)
	if metrics.FQDNSelectors.IsEnabled() {
		metrics.FQDNSelectors.Set(float64(len(n.allSelectors)))
	}

	// Re-compute labels for affected names and IPs
	selectedNamesAndIPs := n.mapSelectorsToNamesLocked(selector)
	n.updateMetadata(deriveLabelsForNames(selectedNamesAndIPs, n.allSelectors))
}

// NewNameManager creates an initialized NameManager.
// When config.Cache is nil, the global fqdn.DefaultDNSCache is used.
func NewNameManager(config Config) *NameManager {

	if config.Cache == nil {
		config.Cache = NewDNSCache(0)
	}

	if config.GetEndpointsDNSInfo == nil {
		config.GetEndpointsDNSInfo = func(_ string) []EndpointDNSInfo {
			return nil
		}
	}

	n := &NameManager{
		config:       config,
		allSelectors: make(map[api.FQDNSelector]*regexp.Regexp),
		cache:        config.Cache,
		manager:      controller.NewManager(),
		nameLocks:    make([]*lock.Mutex, option.Config.DNSProxyLockCount),
	}

	for i := range n.nameLocks {
		n.nameLocks[i] = &lock.Mutex{}
	}

	return n
}

// UpdateGenerateDNS inserts the new DNS information into the cache. If the IPs
// have changed for a name they will be reflected in updatedDNSIPs.
func (n *NameManager) UpdateGenerateDNS(ctx context.Context, lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) *errgroup.Group {
	n.RWMutex.Lock()
	defer n.RWMutex.Unlock()

	// Update IPs in n
	updatedDNSNames, ipcacheRevision := n.updateDNSIPs(lookupTime, updatedDNSIPs)
	for dnsName, IPs := range updatedDNSNames {
		log.WithFields(logrus.Fields{
			"matchName": dnsName,
			"IPs":       IPs,
		}).Debug("Updated FQDN with new IPs")
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return n.config.IPCache.WaitForRevision(ctx, ipcacheRevision)
	})
	return g
}

func (n *NameManager) CompleteBootstrap() {
	n.Lock()
	defer n.Unlock()

	n.bootstrapCompleted = true
	if len(n.restoredPrefixes) > 0 {
		log.WithField("prefixes", len(n.restoredPrefixes)).Debug("Removing restored IPCache labels")

		// The following logic needs to match the restoration logic in RestoreCaches
		ipcacheUpdates := make([]ipcache.MU, 0, len(n.restoredPrefixes))
		for prefix := range n.restoredPrefixes {
			ipcacheUpdates = append(ipcacheUpdates, ipcache.MU{
				Prefix:   prefix,
				Source:   source.Restored,
				Resource: restorationIPCacheResource,
				Metadata: []ipcache.IPMetadata{
					labels.Labels{}, // remove restored labels
				},
			})
		}
		n.config.IPCache.RemoveMetadataBatch(ipcacheUpdates...)
		n.restoredPrefixes = nil

		checkpointPath := filepath.Join(option.Config.StateDir, checkpointFile)
		if err := os.Remove(checkpointPath); err != nil {
			log.WithError(err).WithField(logfields.Path, checkpointPath).
				Debug("Failed to remove checkpoint file")
		}
	}
}

// updateDNSIPs updates the IPs for each DNS name in updatedDNSIPs.
// It returns:
// updatedNames: a map of DNS names to all the valid IPs we store for each.
// ipcacheRevision: a revision number to pass to WaitForRevision()
func (n *NameManager) updateDNSIPs(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) (updatedNames map[string][]netip.Addr, ipcacheRevision uint64) {
	updatedNames = make(map[string][]netip.Addr, len(updatedDNSIPs))
	updatedMetadata := make(map[string]nameMetadata, len(updatedDNSIPs))

	for dnsName, lookupIPs := range updatedDNSIPs {
		updated := n.updateIPsForName(lookupTime, dnsName, lookupIPs.IPs, lookupIPs.TTL)

		// The IPs didn't change. No more to be done for this dnsName
		if !updated && n.bootstrapCompleted {
			log.WithFields(logrus.Fields{
				"dnsName":   dnsName,
				"lookupIPs": lookupIPs,
			}).Debug("FQDN: IPs didn't change for DNS name")
			continue
		}

		// record the IPs that were different
		updatedNames[dnsName] = lookupIPs.IPs

		// accumulate the new labels affected by new IPs
		if len(n.allSelectors) == 0 {
			log.WithFields(logrus.Fields{
				"dnsName":   dnsName,
				"lookupIPs": lookupIPs,
			}).Debug("FQDN: No selectors registered for updates")
			continue
		}

		// derive labels for this DNS name
		nameLabels := deriveLabelsForName(dnsName, n.allSelectors)
		if len(nameLabels) == 0 {
			// If no selectors care about this name, then skip IPCache updates
			// for this name.
			// If any selectors/ are added later, ipcache insertion will happen then.
			continue
		}

		updatedMetadata[dnsName] = nameMetadata{
			addrs:  lookupIPs.IPs,
			labels: nameLabels,
		}
	}

	// If new IPs were detected, and these IPs are selected by selectors,
	// then ensure they have an identity allocated to them via the ipcache.
	ipcacheRevision = n.updateMetadata(updatedMetadata)
	return updatedNames, ipcacheRevision
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// updated is true when the new IPs differ from the old IPs
func (n *NameManager) updateIPsForName(lookupTime time.Time, dnsName string, newIPs []netip.Addr, ttl int) (updated bool) {
	oldCacheIPs := n.cache.Lookup(dnsName)

	if n.config.MinTTL > ttl {
		ttl = n.config.MinTTL
	}

	changed := n.cache.Update(lookupTime, dnsName, newIPs, ttl)
	if !changed { // Changed may have false positives, but not false negatives
		return false
	}

	newCacheIPs := n.cache.Lookup(dnsName) // DNSCache returns IPs unsorted

	// The 0 checks below account for an unlike race condition where this
	// function is called with already expired data and if other cache data
	// from before also expired.
	if len(oldCacheIPs) != len(newCacheIPs) || len(oldCacheIPs) == 0 {
		return true
	}

	ip.SortAddrList(oldCacheIPs) // sorts in place
	ip.SortAddrList(newCacheIPs)

	return !slices.Equal(oldCacheIPs, newCacheIPs)
}

func ipcacheResource(dnsName string) ipcacheTypes.ResourceID {
	return ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindDaemon, "fqdn-name-manager", dnsName)
}

// updateMetadata updates (i.e. upserts or removes) the metadata in IPCache for
// each (name, IP) pair provided in nameToMetadata.
func (n *NameManager) updateMetadata(nameToMetadata map[string]nameMetadata) (ipcacheRevision uint64) {
	var ipcacheUpserts, ipcacheRemovals []ipcache.MU

	for dnsName, metadata := range nameToMetadata {
		var updates []ipcache.MU
		resource := ipcacheResource(dnsName)

		if option.Config.Debug {
			log.WithFields(logrus.Fields{
				"name":     dnsName,
				"prefixes": metadata.addrs,
				"labels":   metadata.labels,
			}).Debug("Updating prefix labels in IPCache")
		}

		for _, addr := range metadata.addrs {
			updates = append(updates, ipcache.MU{
				Prefix:   netip.PrefixFrom(addr, addr.BitLen()),
				Source:   source.Generated,
				Resource: resource,
				Metadata: []ipcache.IPMetadata{
					metadata.labels,
				},
			})
		}

		// If labels are empty (i.e. this domain is no longer selected),
		// then we want to the labels of our resource owner
		if len(metadata.labels) > 0 {
			ipcacheUpserts = append(ipcacheUpserts, updates...)
		} else {
			ipcacheRemovals = append(ipcacheRemovals, updates...)
		}
	}

	if len(ipcacheUpserts) > 0 {
		ipcacheRevision = n.config.IPCache.UpsertMetadataBatch(ipcacheUpserts...)
	}
	if len(ipcacheRemovals) > 0 {
		ipcacheRevision = n.config.IPCache.RemoveMetadataBatch(ipcacheRemovals...)
	}

	return ipcacheRevision
}

// maybeRemoveMetadata removes the ipcache metadata from every (name, IP) pair
// in maybeRemoved, as long as that (name, IP) is not still in the dns cache.
func (n *NameManager) maybeRemoveMetadata(maybeRemoved map[netip.Addr][]string) {
	// Need to take an RLock here so that no DNS updates are processed.
	// Otherwise, we might accidentally remove an IP that is newly inserted.
	n.RWMutex.RLock()
	defer n.RWMutex.RUnlock()

	n.cache.RLock()
	ipCacheUpdates := make([]ipcache.MU, 0, len(maybeRemoved))
	for ip, names := range maybeRemoved {
		for _, name := range names {
			if !n.cache.entryExistsLocked(name, ip) {
				ipCacheUpdates = append(ipCacheUpdates, ipcache.MU{
					Prefix:   netip.PrefixFrom(ip, ip.BitLen()),
					Source:   source.Generated,
					Resource: ipcacheResource(name),
					Metadata: []ipcache.IPMetadata{
						labels.Labels{}, // remove all labels for this (ip, name) pair
					},
				})
			}
		}
	}
	n.cache.RUnlock()
	n.config.IPCache.RemoveMetadataBatch(ipCacheUpdates...)
}

// LockName is used to serialize  parallel end-to-end updates to the same name.
//
// It is needed due to some subtleties around NameManager locks and
// policy updates. Specifically, we unlock the NameManager after updates
// are queued to endpoints, but *before* changes are pushed to policy maps.
// So, if a second request comes in during this state, it may encounter
// policy drops until the policy updates are complete.
//
// Serializing on names prevents this.
//
// Rather than having a potentially unbounded set of per-name locks, this
// buckets names in to a set of locks. The lock count is configurable.
func (n *NameManager) LockName(name string) {
	idx := nameLockIndex(name, option.Config.DNSProxyLockCount)
	n.nameLocks[idx].Lock()
}

// UnlockName releases a lock previously acquired by LockName()
func (n *NameManager) UnlockName(name string) {
	idx := nameLockIndex(name, option.Config.DNSProxyLockCount)
	n.nameLocks[idx].Unlock()
}

// nameLockIndex hashes the DNS name to a uint32, then returns that
// mod the bucket count.
func nameLockIndex(name string, cnt int) uint32 {
	h := fnv.New32()
	_, _ = h.Write([]byte(name)) // cannot return error
	return h.Sum32() % uint32(cnt)
}

type nameMetadata struct {
	addrs  []netip.Addr
	labels labels.Labels // if empty, metadata will be removed for this name
}

// deriveLabelsForName derives what `fqdn:` labels we want to associate with
// IPs for this DNS name, i.e. what selectors match the DNS name.
func deriveLabelsForName(dnsName string, selectors map[api.FQDNSelector]*regexp.Regexp) labels.Labels {
	lbls := labels.Labels{}
	for fqdnSel, fqdnRegex := range selectors {
		matches := fqdnRegex.MatchString(dnsName)
		if matches {
			l := fqdnSel.IdentityLabel()
			lbls[l.Key] = l
		}
	}
	return lbls
}

// deriveLabelsForNames derives the labels for all names found in nameToIPs
func deriveLabelsForNames(nameToIPs map[string][]netip.Addr, selectors map[api.FQDNSelector]*regexp.Regexp) (namesWithMetadata map[string]nameMetadata) {
	namesWithMetadata = make(map[string]nameMetadata, len(nameToIPs))
	for dnsName, addrs := range nameToIPs {
		namesWithMetadata[dnsName] = nameMetadata{
			addrs:  addrs,
			labels: deriveLabelsForName(dnsName, selectors),
		}
	}
	return namesWithMetadata
}
