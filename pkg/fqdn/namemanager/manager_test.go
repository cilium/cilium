// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"context"
	"net/netip"
	"regexp"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

type dummyOwner struct {
	mutex lock.RWMutex
	cache map[string]identity.IdentityMap
}

func newDummyOwner() *dummyOwner {
	return &dummyOwner{
		cache: make(map[string]identity.IdentityMap),
	}
}

func (d *dummyOwner) UpdateIdentities(added, deleted identity.IdentityMap) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	for id, lbls := range added {
		for _, lbl := range lbls {
			m, ok := d.cache[lbl.Key]
			if !ok {
				m = make(identity.IdentityMap)
				d.cache[lbl.Key] = m
			}
			m[id] = lbls
		}
	}
	for id, lbls := range deleted {
		for _, lbl := range lbls {
			m, ok := d.cache[lbl.Key]
			if ok {
				delete(m, id)
			}
			if len(m) == 0 {
				delete(d.cache, lbl.Key)
			}
		}
	}
}

func (d *dummyOwner) GetIdentityByLabels(lbls labels.Labels) identity.NumericIdentity {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	for lblKey := range lbls {
		m := d.cache[lblKey]
	lbl_arr_check:
		for id, lblArr := range m {
			for _, lbl := range lblArr {
				if _, ok := lbls[lbl.Key]; !ok {
					continue lbl_arr_check
				}
			}
			return id
		}
	}
	return 0
}

func (d *dummyOwner) GetNodeSuffix() string {
	return "foo"
}

var (
	ciliumIOSel = api.FQDNSelector{
		MatchName: "cilium.io",
	}

	githubSel = api.FQDNSelector{
		MatchName: "github.com",
	}

	ciliumIOSelMatchPattern = api.FQDNSelector{
		MatchPattern: "*cilium.io.",
	}
)

func TestMapIPsToSelectors(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	var (
		ciliumIP1   = netip.MustParseAddr("1.2.3.4")
		ciliumIP2   = netip.MustParseAddr("1.2.3.5")
		nameManager = New(ManagerParams{
			Logger: logger,
			Config: NameManagerConfig{
				MinTTL: 1,
			},
		})
	)

	// Create DNS cache
	now := time.Now()
	cache := nameManager.cache

	// Empty cache.
	nameIPMapping := nameManager.mapSelectorsToNamesLocked(ciliumIOSel)
	require.Empty(t, nameIPMapping)

	// Just one IP.
	ciliumIOName := prepareMatchName(ciliumIOSel.MatchName)
	changed := cache.Update(now, ciliumIOName, []netip.Addr{ciliumIP1}, 100)
	require.True(t, changed)
	nameIPMapping = nameManager.mapSelectorsToNamesLocked(ciliumIOSel)
	require.Len(t, nameIPMapping, 1)
	println(ciliumIOSel.MatchName)
	ciliumIPs, ok := nameIPMapping[ciliumIOName]
	require.True(t, ok)
	require.Len(t, ciliumIPs, 1)
	require.Equal(t, ciliumIP1, ciliumIPs[0])

	// Two IPs now.
	changed = cache.Update(now, ciliumIOName, []netip.Addr{ciliumIP1, ciliumIP2}, 100)
	require.True(t, changed)
	nameIPMapping = nameManager.mapSelectorsToNamesLocked(ciliumIOSel)
	require.Len(t, nameIPMapping, 1)
	ciliumIPs, ok = nameIPMapping[ciliumIOName]
	require.True(t, ok)
	require.Len(t, ciliumIPs, 2)
	ip.SortAddrList(ciliumIPs)
	require.Equal(t, ciliumIP1, ciliumIPs[0])
	require.Equal(t, ciliumIP2, ciliumIPs[1])

	// Test with a MatchPattern.
	nameIPMapping = nameManager.mapSelectorsToNamesLocked(ciliumIOSelMatchPattern)
	require.Len(t, nameIPMapping, 1)
	ciliumIPs, ok = nameIPMapping[ciliumIOName]
	require.True(t, ok)
	require.Len(t, ciliumIPs, 2)
	ip.SortAddrList(ciliumIPs)
	require.Equal(t, ciliumIP1, ciliumIPs[0])
	require.Equal(t, ciliumIP2, ciliumIPs[1])
}

func TestNameManagerIPCacheUpdates(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	ipc := newMockIPCache()
	owner := newDummyOwner()

	localIDMap := make(map[identity.NumericIdentity]labels.Labels)
	mgr := identityCache.NewCachingIdentityAllocator(owner, identityCache.AllocatorConfig{EnableOperatorManageCIDs: false})
	mgr.LocalIdentityChanges().Observe(context.Background(), func(idChange identityCache.IdentityChange) {
		if idChange.ID.HasLocalScope() {
			localIDMap[idChange.ID] = idChange.Labels
		}
	}, func(err error) {

	})
	nameManager := New(ManagerParams{
		Logger: logger,
		Config: NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          option.Config.StateDir,
		},
		IPCache:           ipc,
		IdentityAllocator: mgr,
	})

	nameManager.RegisterFQDNSelector(ciliumIOSel)
	// Wait for the namemanager to trigger allocation
	// (it allocates on a Millisecond trigger).
	time.Sleep(time.Millisecond * 50)
	for _, lbls := range identityLabels(ciliumIOSel) {
		id := owner.GetIdentityByLabels(lbls)
		changeLbls, ok := localIDMap[id]
		require.Truef(t, ok, "local ID changes not found for id %d in changes %+v", id, localIDMap)
		require.Equal(t, lbls, changeLbls)
	}
	// Simulate lookup for single selector
	prefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("1.1.1.1/32"))
	nameManager.UpdateGenerateDNS(context.TODO(), time.Now(), dns.FQDN("cilium.io"), &fqdn.DNSIPRecords{TTL: 60, IPs: []netip.Addr{prefix.AsPrefix().Addr()}})
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel()}), ipc.labelsForPrefix(prefix))

	// Add match pattern
	nameManager.RegisterFQDNSelector(ciliumIOSelMatchPattern)
	// Wait for the namemanager to trigger allocation
	// (it allocates on a Millisecond trigger).
	time.Sleep(time.Millisecond * 50)
	for _, lbls := range identityLabels(ciliumIOSelMatchPattern) {
		id := owner.GetIdentityByLabels(lbls)
		changeLbls, ok := localIDMap[id]
		require.Truef(t, ok, "local ID changes not found for id %d in changes %+v", id, localIDMap)
		require.Equal(t, lbls, changeLbls)
	}
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), ciliumIOSelMatchPattern.IdentityLabel()}), ipc.labelsForPrefix(prefix))

	// Remove cilium.io matchname, add github.com match name
	nameManager.RegisterFQDNSelector(githubSel)
	nameManager.UnregisterFQDNSelector(ciliumIOSel)
	// Wait for the namemanager to trigger allocation
	// (it allocates on a Millisecond trigger).
	time.Sleep(time.Millisecond * 50)
	for _, lbls := range identityLabels(githubSel) {
		id := owner.GetIdentityByLabels(lbls)
		changeLbls, ok := localIDMap[id]
		require.Truef(t, ok, "local ID changes not found for id %d in changes %+v", id, localIDMap)
		require.Equal(t, lbls, changeLbls)
	}
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel()}), ipc.labelsForPrefix(prefix))

	// Same IP matched by two selectors
	nameManager.UpdateGenerateDNS(context.TODO(), time.Now(), dns.FQDN("github.com"), &fqdn.DNSIPRecords{TTL: 60, IPs: []netip.Addr{prefix.AsPrefix().Addr()}})
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel(), githubSel.IdentityLabel()}), ipc.labelsForPrefix(prefix))

	// Additional unique IPs for each selector
	githubPrefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.2/32"))
	awesomePrefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.3/32"))
	n := time.Now()
	nameManager.UpdateGenerateDNS(context.TODO(), n, dns.FQDN("github.com"), &fqdn.DNSIPRecords{TTL: 60, IPs: []netip.Addr{githubPrefix.AsPrefix().Addr()}})
	nameManager.UpdateGenerateDNS(context.TODO(), n, dns.FQDN("awesomecilium.io"), &fqdn.DNSIPRecords{TTL: 60, IPs: []netip.Addr{awesomePrefix.AsPrefix().Addr()}})
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel(), githubSel.IdentityLabel()}), ipc.labelsForPrefix(prefix))
	require.Equal(t, labels.FromSlice([]labels.Label{githubSel.IdentityLabel()}), ipc.labelsForPrefix(githubPrefix))
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel()}), ipc.labelsForPrefix(awesomePrefix))

	// Removing selector should remove from IPCache
	nameManager.UnregisterFQDNSelector(ciliumIOSelMatchPattern)
	require.NotContains(t, ipc.metadata, awesomePrefix)
	require.Equal(t, labels.FromSlice([]labels.Label{githubSel.IdentityLabel()}), ipc.labelsForPrefix(prefix))
	require.Equal(t, labels.FromSlice([]labels.Label{githubSel.IdentityLabel()}), ipc.labelsForPrefix(githubPrefix))
}

func Test_deriveLabelsForNames(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	ciliumIORe, err := ciliumIOSel.ToRegex()
	require.NoError(t, err)
	githubRe, err := githubSel.ToRegex()
	require.NoError(t, err)
	ciliumIOSelMatchPatternRe, err := ciliumIOSelMatchPattern.ToRegex()
	require.NoError(t, err)

	selectors := map[api.FQDNSelector]*regexp.Regexp{
		ciliumIOSel:             ciliumIORe,
		githubSel:               githubRe,
		ciliumIOSelMatchPattern: ciliumIOSelMatchPatternRe,
	}

	nomatchIP := netip.MustParseAddr("10.10.0.1")
	githubIP := netip.MustParseAddr("10.20.0.1")
	ciliumIP1 := netip.MustParseAddr("10.30.0.1")
	ciliumIP2 := netip.MustParseAddr("10.30.0.2")

	names := map[string][]netip.Addr{
		"nomatch.local.":    {nomatchIP},
		"github.com.":       {githubIP},
		"cilium.io.":        {ciliumIP1},
		"awesomecilium.io.": {ciliumIP1, ciliumIP2},
	}

	require.Equal(t, map[string]nameMetadata{
		"nomatch.local.": {
			addrs:  []netip.Addr{nomatchIP},
			labels: labels.Labels{},
		},
		"github.com.": {
			addrs:  []netip.Addr{githubIP},
			labels: labels.NewLabelsFromSortedList("fqdn:github.com"),
		},
		"cilium.io.": {
			addrs:  []netip.Addr{ciliumIP1},
			labels: labels.NewLabelsFromSortedList("fqdn:*cilium.io.;fqdn:cilium.io"),
		},
		"awesomecilium.io.": {
			addrs:  []netip.Addr{ciliumIP1, ciliumIP2},
			labels: labels.NewLabelsFromSortedList("fqdn:*cilium.io."),
		},
	}, deriveLabelsForNames(names, selectors))
}

// makeIPs generates count sequential IPv4 IPs
func makeIPs(count uint32) []netip.Addr {
	ips := make([]netip.Addr, 0, count)
	for i := uint32(0); i < count; i++ {
		ips = append(ips, netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i >> 0)}))
	}
	return ips
}

type mockIPCache struct {
	metadata map[cmtypes.PrefixCluster]map[ipcacheTypes.ResourceID]labels.Labels
}

func newMockIPCache() *mockIPCache {
	return &mockIPCache{
		metadata: make(map[cmtypes.PrefixCluster]map[ipcacheTypes.ResourceID]labels.Labels),
	}
}

func (m *mockIPCache) labelsForPrefix(prefix cmtypes.PrefixCluster) labels.Labels {
	lbls := labels.Labels{}
	for _, l := range m.metadata[prefix] {
		lbls.MergeLabels(l)
	}
	return lbls
}

func (m *mockIPCache) UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	for _, mu := range updates {
		prefixMetadata, ok := m.metadata[mu.Prefix]
		if !ok {
			prefixMetadata = make(map[ipcacheTypes.ResourceID]labels.Labels)
		}

		for _, aux := range mu.Metadata {
			if lbls, ok := aux.(labels.Labels); ok {
				prefixMetadata[mu.Resource] = lbls
				break
			}
		}

		m.metadata[mu.Prefix] = prefixMetadata
	}

	return 0
}

func (m *mockIPCache) RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	for _, mu := range updates {
		for _, aux := range mu.Metadata {
			if _, ok := aux.(labels.Labels); ok {
				delete(m.metadata[mu.Prefix], mu.Resource)
				break
			}
		}

		if len(m.metadata[mu.Prefix]) == 0 {
			delete(m.metadata, mu.Prefix)
		}
	}

	return 0
}

func (m *mockIPCache) WaitForRevision(ctx context.Context, rev uint64) error {
	return nil
}
