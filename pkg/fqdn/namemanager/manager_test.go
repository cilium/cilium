// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/time"
)

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
	res := cache.Update(now, ciliumIOName, []netip.Addr{ciliumIP1}, 100)
	require.Equal(t, fqdn.UpdateStatus{Updated: true, Upserted: true}, res)
	nameIPMapping = nameManager.mapSelectorsToNamesLocked(ciliumIOSel)
	require.Len(t, nameIPMapping, 1)
	println(ciliumIOSel.MatchName)
	ciliumIPs, ok := nameIPMapping[ciliumIOName]
	require.True(t, ok)
	require.Len(t, ciliumIPs, 1)
	require.Equal(t, ciliumIP1, ciliumIPs[0])

	// Two IPs now.
	res = cache.Update(now, ciliumIOName, []netip.Addr{ciliumIP1, ciliumIP2}, 100)
	require.Equal(t, fqdn.UpdateStatus{Updated: true, Upserted: true}, res)
	nameIPMapping = nameManager.mapSelectorsToNamesLocked(ciliumIOSel)
	require.Len(t, nameIPMapping, 1)
	ciliumIPs, ok = nameIPMapping[ciliumIOName]
	require.True(t, ok)
	require.Len(t, ciliumIPs, 2)
	ip.SortAddrList(ciliumIPs)
	require.Equal(t, ciliumIP1, ciliumIPs[0])
	require.Equal(t, ciliumIP2, ciliumIPs[1])

	// Two IPs again with long ttl.
	res = cache.Update(now, ciliumIOName, []netip.Addr{ciliumIP1, ciliumIP2}, 101)
	require.Equal(t, fqdn.UpdateStatus{Updated: true, Upserted: false}, res)
	nameIPMapping = nameManager.mapSelectorsToNamesLocked(ciliumIOSel)
	require.Len(t, nameIPMapping, 1)
	ciliumIPs, ok = nameIPMapping[ciliumIOName]
	require.True(t, ok)
	require.Len(t, ciliumIPs, 2)
	ip.SortAddrList(ciliumIPs)
	require.Equal(t, ciliumIP1, ciliumIPs[0])
	require.Equal(t, ciliumIP2, ciliumIPs[1])

	// Two IPs again with short ttl.
	res = cache.Update(now, ciliumIOName, []netip.Addr{ciliumIP1, ciliumIP2}, 1)
	require.Equal(t, fqdn.UpdateStatus{Updated: false, Upserted: false}, res)
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

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           t.Context(),
		Logger:            logger,
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		IdentityUpdater:   &dummyIdentityUpdater{},
	})
	ipc.TriggerLabelInjection()
	defer ipc.Shutdown()
	nameManager := New(ManagerParams{
		Logger: logger,
		Config: NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          option.Config.StateDir,
		},
		IPCache: ipc,
	})

	err := ipc.WaitForRevision(t.Context(), nameManager.RegisterFQDNSelector(ciliumIOSel))
	require.NoError(t, err)

	// Simulate lookup for single selector
	prefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("1.1.1.1/32"))
	<-nameManager.UpdateGenerateDNS(context.TODO(), time.Now(), dns.FQDN("cilium.io"), &fqdn.DNSIPRecords{TTL: 60, IPs: []netip.Addr{prefix.AsPrefix().Addr()}})

	id, found := ipc.LookupByPrefix(prefix.String())
	require.True(t, found)
	ident := ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)

	// Add match pattern
	err = ipc.WaitForRevision(t.Context(), nameManager.RegisterFQDNSelector(ciliumIOSelMatchPattern))
	require.NoError(t, err)

	id, found = ipc.LookupByPrefix(prefix.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), ciliumIOSelMatchPattern.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)

	// Remove cilium.io matchname, add github.com match name
	nameManager.RegisterFQDNSelector(githubSel)
	err = ipc.WaitForRevision(t.Context(), nameManager.UnregisterFQDNSelector(ciliumIOSel))
	require.NoError(t, err)

	id, found = ipc.LookupByPrefix(prefix.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)

	// Same IP matched by two selectors
	<-nameManager.UpdateGenerateDNS(context.TODO(), time.Now(), dns.FQDN("github.com"), &fqdn.DNSIPRecords{TTL: 60, IPs: []netip.Addr{prefix.AsPrefix().Addr()}})
	id, found = ipc.LookupByPrefix(prefix.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel(), githubSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)

	// Additional unique IPs for each selector
	githubPrefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.2/32"))
	awesomePrefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.3/32"))
	n := time.Now()
	<-nameManager.UpdateGenerateDNS(context.TODO(), n, dns.FQDN("github.com"), &fqdn.DNSIPRecords{TTL: 60, IPs: []netip.Addr{githubPrefix.AsPrefix().Addr()}})
	<-nameManager.UpdateGenerateDNS(context.TODO(), n, dns.FQDN("awesomecilium.io"), &fqdn.DNSIPRecords{TTL: 60, IPs: []netip.Addr{awesomePrefix.AsPrefix().Addr()}})
	id, found = ipc.LookupByPrefix(prefix.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel(), githubSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)
	id, found = ipc.LookupByPrefix(githubPrefix.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{githubSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)
	id, found = ipc.LookupByPrefix(awesomePrefix.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)

	// Removing selector should remove from IPCache
	err = ipc.WaitForRevision(t.Context(), nameManager.UnregisterFQDNSelector(ciliumIOSelMatchPattern))
	require.NoError(t, err)
	id, found = ipc.LookupByPrefix(awesomePrefix.String())
	require.False(t, found)

	id, found = ipc.LookupByPrefix(prefix.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{githubSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)

	id, found = ipc.LookupByPrefix(githubPrefix.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{githubSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)

}

// Test TestNameManagerGCConsistency test edge-cases around ordering of cache upserts,
// as well as endpoints coming online. It helps catch correctness issues involving IPs
// race between the global and the local dns caches where some operations are not in sync
func TestNameManagerGCConsistency(t *testing.T) {
	logger := hivetest.Logger(t)
	lookupTime := time.Now()
	prefixOne := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("1.1.1.1/32"))
	prefixTwo := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("2.1.1.1/32"))
	prefixThree := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("3.1.1.1/32"))
	prefixFour := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("4.1.1.1/32"))

	epMgr := mgrMock{
		logger: logger,
		eps:    make(sets.Set[*endpoint.Endpoint]),
	}
	ep := &endpoint.Endpoint{ID: uint16(1), IPv4: netip.MustParseAddr("10.96.0.1"), SecurityIdentity: &identity.Identity{
		ID: identity.NumericIdentity(int(identity.GetMaximumAllocationIdentity(option.Config.ClusterID))),
	},
		DNSZombies: fqdn.NewDNSZombieMappings(logger, 10000, 10000),
		DNSHistory: fqdn.NewDNSCache(1),
	}
	ep.UpdateLogger(nil)
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           t.Context(),
		Logger:            logger,
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		IdentityUpdater:   &dummyIdentityUpdater{},
	})
	ipc.TriggerLabelInjection()
	defer ipc.Shutdown()
	nameManager := New(ManagerParams{
		Logger: logger,
		Config: NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          option.Config.StateDir,
		},
		EPMgr:   &epMgr,
		IPCache: ipc,
	})
	// Manually configure bootstrap to be done to fully test manager end-to-end
	nameManager.bootstrapCompleted = true
	err := ipc.WaitForRevision(t.Context(), nameManager.RegisterFQDNSelector(ciliumIOSel))
	require.NoError(t, err)

	// Add initial IP to local cache before adding endpoint to manager
	// We do this to mimic the GC starting and dumping endpoints before the endpoint is added to the manager
	ep.DNSHistory.Update(lookupTime, dns.FQDN("cilium.io"), []netip.Addr{prefixOne.AsPrefix().Addr()}, 10)

	// Run GC to ensure the IP<>name mapping is not added to the global cache
	require.NoError(t, nameManager.doGC(t.Context()))

	// Ensure all IPcache operations done by GC have been processed
	err = ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch())
	require.NoError(t, err)

	require.Empty(t, nameManager.cache.LookupIP(prefixOne.AsPrefix().Addr()))
	_, found := ipc.LookupByPrefix(prefixOne.String())
	require.False(t, found)
	require.NotContains(t, nameManager.cache.LookupIP(prefixOne.AsPrefix().Addr()), dns.FQDN("cilium.io"))

	// Upsert to global cache and ensure its present
	<-nameManager.UpdateGenerateDNS(t.Context(), lookupTime, dns.FQDN("cilium.io"), &fqdn.DNSIPRecords{TTL: 10, IPs: []netip.Addr{prefixOne.AsPrefix().Addr()}}, ep.DNSHistory)

	id, found := ipc.LookupByPrefix(prefixOne.String())
	require.True(t, found)
	ident := ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)
	require.Contains(t, nameManager.cache.LookupIP(prefixOne.AsPrefix().Addr()), dns.FQDN("cilium.io"))

	// Run GC and ensure it's still present
	// This is again assuming the GC started before the endpoint was created, so the manager still does not know about the endpoint
	require.NoError(t, nameManager.doGC(t.Context()))

	// Ensure all IPcache operations done by GC have been processed
	err = ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch())
	require.NoError(t, err)

	id, found = ipc.LookupByPrefix(prefixOne.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)
	require.Contains(t, nameManager.cache.LookupIP(prefixOne.AsPrefix().Addr()), dns.FQDN("cilium.io"))

	// Add endpoint to the manager
	epMgr.UpsertEndpoint(ep)

	// After endpoint is added, ensure it's still in the cache
	require.NoError(t, nameManager.doGC(t.Context()))

	// Ensure all IPcache operations done by GC have been processed
	err = ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch())
	require.NoError(t, err)

	id, found = ipc.LookupByPrefix(prefixOne.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)
	require.Contains(t, nameManager.cache.LookupIP(prefixOne.AsPrefix().Addr()), dns.FQDN("cilium.io"))

	// Insert old prefix that will end up as zombie
	ep.DNSHistory.Update(lookupTime.Add(-time.Hour), dns.FQDN("cilium.io"), []netip.Addr{prefixTwo.AsPrefix().Addr()}, 10)
	<-nameManager.UpdateGenerateDNS(t.Context(), lookupTime, dns.FQDN("cilium.io"), &fqdn.DNSIPRecords{TTL: 10, IPs: []netip.Addr{prefixTwo.AsPrefix().Addr()}}, ep.DNSHistory)

	// Run GC and check that the prefix is upserted to the ipcache
	require.NoError(t, nameManager.doGC(t.Context()))

	// Ensure all IPcache operations done by GC have been processed
	err = ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch())
	require.NoError(t, err)

	id, found = ipc.LookupByPrefix(prefixTwo.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)
	require.Contains(t, nameManager.cache.LookupIP(prefixTwo.AsPrefix().Addr()), dns.FQDN("cilium.io"))

	// Add another prefix to local cache
	ep.DNSHistory.Update(lookupTime, dns.FQDN("cilium.io"), []netip.Addr{prefixThree.AsPrefix().Addr()}, 10)

	// Run GC to ensure the IP<>name mapping is not added to the global cache yet
	require.NoError(t, nameManager.doGC(t.Context()))

	// Ensure all IPcache operations done by GC have been processed
	err = ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch())
	require.NoError(t, err)

	require.Empty(t, nameManager.cache.LookupIP(prefixThree.AsPrefix().Addr()))

	_, found = ipc.LookupByPrefix(prefixThree.String())
	require.False(t, found)
	require.NotContains(t, nameManager.cache.LookupIP(prefixThree.AsPrefix().Addr()), dns.FQDN("cilium.io"))

	// Upsert to global cache and ensure its present
	<-nameManager.UpdateGenerateDNS(t.Context(), lookupTime, dns.FQDN("cilium.io"), &fqdn.DNSIPRecords{TTL: 10, IPs: []netip.Addr{prefixThree.AsPrefix().Addr()}}, ep.DNSHistory)

	id, found = ipc.LookupByPrefix(prefixThree.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)
	require.Contains(t, nameManager.cache.LookupIP(prefixThree.AsPrefix().Addr()), dns.FQDN("cilium.io"))

	// Run GC and ensure it's still present
	require.NoError(t, nameManager.doGC(t.Context()))

	// Ensure all IPcache operations done by GC have been processed
	err = ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch())
	require.NoError(t, err)

	id, found = ipc.LookupByPrefix(prefixThree.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)

	// Lock endpoint manager to freeze GC in time
	epMgr.mu.Lock()
	wg := sync.WaitGroup{}
	wg.Go(func() {
		require.NoError(t, nameManager.doGC(t.Context()))

		// Ensure all IPcache operations done by GC have been processed
		err = ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch())
		require.NoError(t, err)
	})

	// Sleep for a short while to be sure GC is blocked by epMgr lock
	time.Sleep(100 * time.Millisecond)

	// Insert a "back in time" lookup to both local and global cache. This to ensure its immediately put in zombies
	ep.DNSHistory.Update(lookupTime.Add(-time.Hour), dns.FQDN("cilium.io"), []netip.Addr{prefixFour.AsPrefix().Addr()}, 10)
	<-nameManager.UpdateGenerateDNS(t.Context(), lookupTime.Add(-time.Hour), dns.FQDN("cilium.io"), &fqdn.DNSIPRecords{TTL: 10, IPs: []netip.Addr{prefixFour.AsPrefix().Addr()}}, ep.DNSHistory)
	id, found = ipc.LookupByPrefix(prefixFour.String())
	require.True(t, found)
	ident = ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Equal(t, labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), labels.ParseLabel("reserved:world-ipv4")}), ident.Labels)
	require.Contains(t, nameManager.cache.LookupIP(prefixFour.AsPrefix().Addr()), dns.FQDN("cilium.io"))

	// Explicitly GC the local cache to ensure the IP goes fully unused by any endpoint - except for the zombie.
	// However, since the endpoint is deleted by the time of the next endpointManager GC, it won't be seen by the
	// endpoint. This can effectively not happen, but it's a good test to ensure that GC won't delete an IP<>name mapping
	// without cleaning it up from the ipcache.
	ep.DNSHistory.GC(time.Now(), ep.DNSZombies)

	epMgr.RemoveEndpointLocked(ep)
	epMgr.mu.Unlock()

	wg.Wait()
	// Run GC again twice to ensure all pending lookups have been processed.
	require.NoError(t, nameManager.doGC(t.Context()))
	require.NoError(t, nameManager.doGC(t.Context()))

	// Ensure all IPcache operations done by GC have been processed
	err = ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch())
	require.NoError(t, err)

	require.Empty(t, nameManager.cache.Dump())

	// Ensure all IPs are gone, even if selector is still registered
	for _, p := range []cmtypes.PrefixCluster{prefixOne, prefixTwo, prefixThree, prefixFour} {
		id, found = ipc.LookupByPrefix(p.String())
		require.False(t, found)
	}
}

func Test_deriveLabelsForNames(t *testing.T) {
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
	for i := range uint32(count) {
		ips = append(ips, netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i >> 0)}))
	}
	return ips
}

type dummyIdentityUpdater struct{}

func (*dummyIdentityUpdater) UpdateIdentities(added, deleted identity.IdentityMap) <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

type mgrMock struct {
	logger *slog.Logger
	eps    sets.Set[*endpoint.Endpoint]
	mu     lock.Mutex
}

func (mgr *mgrMock) Lookup(id string) (*endpoint.Endpoint, error) {
	return nil, fmt.Errorf("Lookup not implemented")
}

func (mgr *mgrMock) UpsertEndpoint(ep *endpoint.Endpoint) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.eps.Insert(ep)
}
func (mgr *mgrMock) RemoveEndpoint(ep *endpoint.Endpoint) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.eps.Delete(ep)
}

func (mgr *mgrMock) RemoveEndpointLocked(ep *endpoint.Endpoint) {
	mgr.eps.Delete(ep)
}

func (mgr *mgrMock) GetEndpoints() []*endpoint.Endpoint {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.eps.UnsortedList()
}
