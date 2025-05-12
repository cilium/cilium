// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"context"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// The implementation of the NameManager interface.
type manager struct {
	logger *slog.Logger

	lock.RWMutex

	// params is a copy from when this instance was initialized.
	// It is read-only once set
	params ManagerParams

	// allSelectors contains all FQDNSelectors which are present in all policy. We
	// use these selectors to map selectors --> IPs.
	allSelectors map[api.FQDNSelector]*regexp.Regexp

	cache *fqdn.DNSCache

	bootstrapCompleted bool

	// restoredPrefixes contains all prefixes for which we have restored the
	// IPCache metadata from previous Cilium v1.15 installation.
	// Cleared by CompleteBoostrap
	restoredPrefixes sets.Set[netip.Prefix]

	// list of locks used as coordination points for name updates
	// see LockName() for details.
	nameLocks []*lock.Mutex
}

// New creates an initialized NameManager.
func New(params ManagerParams) *manager {
	cache := fqdn.NewDNSCache(params.Config.MinTTL)
	// Disable cleanup tracking on the default DNS cache. This cache simply
	// tracks which api.FQDNSelector are present in policy which apply to
	// locally running endpoints.
	cache.DisableCleanupTrack()

	n := &manager{
		logger:       params.Logger,
		params:       params,
		allSelectors: make(map[api.FQDNSelector]*regexp.Regexp),
		cache:        cache,
		nameLocks:    make([]*lock.Mutex, params.Config.DNSProxyLockCount),
	}

	for i := range n.nameLocks {
		n.nameLocks[i] = &lock.Mutex{}
	}

	// Break Hive import loop -- pass the NameManager back to the SelectorCache.
	// (optional for tests)
	if params.PolicyRepo != nil {
		params.PolicyRepo.GetSelectorCache().SetLocalIdentityNotifier(n)
	}

	// Set up GC and bootstrap jobs
	if params.JobGroup != nil {
		params.JobGroup.Add(job.Timer(
			dnsGCJobName,
			n.doGC,
			DNSGCJobInterval,
		))

		params.JobGroup.Add(job.OneShot(
			"remove-restored-prefixes",
			n.removeRestoredPrefixes,
		))
	}

	return n
}

// RegisterFQDNSelector exposes this FQDNSelector so that the identity labels
// of IPs contained in a DNS response that matches said selector can be
// associated with that selector.
// This function also evaluates if any DNS names in the cache are matched by
// this new selector and updates the labels for those DNS names accordingly.
func (n *manager) RegisterFQDNSelector(selector api.FQDNSelector) {
	n.Lock()
	defer n.Unlock()

	_, exists := n.allSelectors[selector]
	if exists {
		n.logger.Warn("FQDNSelector was already registered for updates.",
			logfields.FQDNSelector, selector,
		)
	} else {
		// This error should never occur since the FQDNSelector has already been
		// validated, but account for it for good measure.
		regex, err := selector.ToRegex()
		if err != nil {
			n.logger.Error("FQDNSelector did not compile to valid regex",
				logfields.Error, err,
				logfields.FQDNSelector, selector,
			)
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
func (n *manager) UnregisterFQDNSelector(selector api.FQDNSelector) {
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

// UpdateGenerateDNS inserts the new DNS information into the cache. If the IPs
// have changed for a name they will be reflected in updatedDNSIPs.
func (n *manager) UpdateGenerateDNS(ctx context.Context, lookupTime time.Time, name string, record *fqdn.DNSIPRecords) <-chan error {
	n.RWMutex.Lock()
	defer n.RWMutex.Unlock()

	// Update IPs in n
	updated, ipcacheRevision := n.updateDNSIPs(lookupTime, name, record)
	if updated {
		n.logger.Debug(
			"Updated FQDN with new IPs",
			logfields.MatchName, name,
			logfields.IPAddrs, record.IPs,
		)
	}

	c := make(chan error)
	go func() {
		c <- n.params.IPCache.WaitForRevision(ctx, ipcacheRevision)
	}()
	return c
}

// removeRestoredPrefixes is a one-shot job. It waits for
// all endpoints to be regenerated, then removes restored ipcache state.
func (n *manager) removeRestoredPrefixes(ctx context.Context, _ cell.Health) error {
	epRestorer, err := n.params.RestorerPromise.Await(ctx)
	if err != nil {
		n.logger.Error("Failed to get endpoint restorer", logfields.Error, err)
		return err
	}
	if err := epRestorer.WaitForEndpointRestore(ctx); err != nil {
		n.logger.Error("Failed to wait for endpoints to regenerate", logfields.Error, err)
		return err
	}

	n.Lock()
	defer n.Unlock()

	n.bootstrapCompleted = true
	if len(n.restoredPrefixes) > 0 {
		n.logger.Debug(
			"Removing restored IPCache labels",
			logfields.LenPrefixes, len(n.restoredPrefixes),
		)

		// The following logic needs to match the restoration logic in RestoreCaches
		ipcacheUpdates := make([]ipcache.MU, 0, len(n.restoredPrefixes))
		for prefix := range n.restoredPrefixes {
			ipcacheUpdates = append(ipcacheUpdates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
				Source:   source.Restored,
				Resource: restorationIPCacheResource,
				Metadata: []ipcache.IPMetadata{
					labels.Labels{}, // remove restored labels
				},
			})
		}
		n.params.IPCache.RemoveMetadataBatch(ipcacheUpdates...)
		n.restoredPrefixes = nil

		checkpointPath := filepath.Join(n.params.Config.StateDir, checkpointFile)
		if err := os.Remove(checkpointPath); err != nil {
			n.logger.Debug(
				"Failed to remove checkpoint file",
				logfields.Error, err,
				logfields.Path, checkpointPath,
			)
		}
	}
	return nil
}

// updateDNSIPs updates the IPs for a DNS name. It returns whether the name's IPs
// changed and ipcacheRevision, a revision number to pass to WaitForRevision()
func (n *manager) updateDNSIPs(lookupTime time.Time, dnsName string, lookupIPs *fqdn.DNSIPRecords) (updated bool, ipcacheRevision uint64) {
	updated = n.updateIPsForName(lookupTime, dnsName, lookupIPs.IPs, lookupIPs.TTL)

	// The IPs didn't change. No more to be done for this dnsName
	if !updated && n.bootstrapCompleted {
		n.logger.Debug(
			"FQDN: IPs didn't change for DNS name",
			logfields.DNSName, dnsName,
			logfields.LookupIPAddrs, lookupIPs,
		)
		return
	}

	// accumulate the new labels affected by new IPs
	if len(n.allSelectors) == 0 {
		n.logger.Debug(
			"FQDN: No selectors registered for updates",
			logfields.DNSName, dnsName,
			logfields.LookupIPAddrs, lookupIPs,
		)
		return
	}

	// derive labels for this DNS name
	nameLabels := deriveLabelsForName(dnsName, n.allSelectors)
	if len(nameLabels) == 0 {
		// If no selectors care about this name, then skip IPCache updates
		// for this name.
		// If any selectors/ are added later, ipcache insertion will happen then.
		return
	}

	updates := map[string]nameMetadata{
		dnsName: {
			addrs:  lookupIPs.IPs,
			labels: nameLabels,
		},
	}

	// If new IPs were detected, and these IPs are selected by selectors,
	// then ensure they have an identity allocated to them via the ipcache.
	ipcacheRevision = n.updateMetadata(updates)
	return updated, ipcacheRevision
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// updated is true when the new IPs differ from the old IPs
func (n *manager) updateIPsForName(lookupTime time.Time, dnsName string, newIPs []netip.Addr, ttl int) (updated bool) {
	oldCacheIPs := n.cache.Lookup(dnsName)

	if n.params.Config.MinTTL > ttl {
		ttl = n.params.Config.MinTTL
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
func (n *manager) updateMetadata(nameToMetadata map[string]nameMetadata) (ipcacheRevision uint64) {
	var ipcacheUpserts, ipcacheRemovals []ipcache.MU

	for dnsName, metadata := range nameToMetadata {
		var updates []ipcache.MU
		resource := ipcacheResource(dnsName)

		n.logger.Debug(
			"Updating prefix labels in IPCache",
			logfields.Name, dnsName,
			logfields.IPAddrs, metadata.addrs,
			logfields.Labels, metadata.labels,
		)

		for _, addr := range metadata.addrs {
			updates = append(updates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, addr.BitLen())),
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
		ipcacheRevision = n.params.IPCache.UpsertMetadataBatch(ipcacheUpserts...)
	}
	if len(ipcacheRemovals) > 0 {
		ipcacheRevision = n.params.IPCache.RemoveMetadataBatch(ipcacheRemovals...)
	}

	return ipcacheRevision
}

// maybeRemoveMetadata removes the ipcache metadata from every (name, IP) pair
// in maybeRemoved, as long as that (name, IP) is not still in the dns cache.
func (n *manager) maybeRemoveMetadata(maybeRemoved map[netip.Addr][]string) {
	// Need to take an RLock here so that no DNS updates are processed.
	// Otherwise, we might accidentally remove an IP that is newly inserted.
	n.RWMutex.RLock()
	defer n.RWMutex.RUnlock()

	n.cache.RemoveKnown(maybeRemoved)
	ipCacheUpdates := make([]ipcache.MU, 0, len(maybeRemoved))
	for ip, names := range maybeRemoved {
		for _, name := range names {
			ipCacheUpdates = append(ipCacheUpdates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(ip, ip.BitLen())),
				Source:   source.Generated,
				Resource: ipcacheResource(name),
				Metadata: []ipcache.IPMetadata{
					labels.Labels{}, // remove all labels for this (ip, name) pair
				},
			})
		}
	}
	n.params.IPCache.RemoveMetadataBatch(ipCacheUpdates...)
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
func (n *manager) LockName(name string) {
	idx := nameLockIndex(name, n.params.Config.DNSProxyLockCount)
	n.nameLocks[idx].Lock()
}

// UnlockName releases a lock previously acquired by LockName()
func (n *manager) UnlockName(name string) {
	idx := nameLockIndex(name, n.params.Config.DNSProxyLockCount)
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

// mapSelectorsToNamesLocked iterates through all DNS Names in the cache and
// evaluates if they match the provided fqdnSelector. If so, the matching DNS
// Name with all its associated IPs is collected.
//
// Returns the mapping of DNS names to all IPs selected by that selector.
func (n *manager) mapSelectorsToNamesLocked(fqdnSelector api.FQDNSelector) (namesIPMapping map[string][]netip.Addr) {
	namesIPMapping = make(map[string][]netip.Addr)

	// lookup matching DNS names
	if len(fqdnSelector.MatchName) > 0 {
		dnsName := prepareMatchName(fqdnSelector.MatchName)
		lookupIPs := n.cache.Lookup(dnsName)
		if len(lookupIPs) > 0 {
			n.logger.Debug(
				"Emitting matching DNS Name -> IPs for FQDNSelector",
				logfields.DNSName, dnsName,
				logfields.IPAddrs, lookupIPs,
				logfields.MatchName, fqdnSelector.MatchName,
			)
			namesIPMapping[dnsName] = lookupIPs
		}
	}

	if len(fqdnSelector.MatchPattern) > 0 {
		// lookup matching DNS names
		dnsPattern := matchpattern.Sanitize(fqdnSelector.MatchPattern)
		patternREStr := matchpattern.ToAnchoredRegexp(dnsPattern)
		var (
			err       error
			patternRE *regexp.Regexp
		)

		if patternRE, err = re.CompileRegex(patternREStr); err != nil {
			n.logger.Error("Error compiling matchPattern", logfields.Error, err)
			return namesIPMapping
		}
		lookupIPs := n.cache.LookupByRegexp(patternRE)

		for dnsName, ips := range lookupIPs {
			if len(ips) > 0 {
				n.logger.Debug(
					"Emitting matching DNS Name -> IPs for FQDNSelector",
					logfields.DNSName, dnsName,
					logfields.IPAddrs, ips,
					logfields.MatchPattern, fqdnSelector.MatchPattern,
				)
				namesIPMapping[dnsName] = append(namesIPMapping[dnsName], ips...)
			}
		}
	}

	return namesIPMapping
}

// prepareMatchName ensures a ToFQDNs.matchName field is used consistently.
func prepareMatchName(matchName string) string {
	return dns.FQDN(matchName)
}
