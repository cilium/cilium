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
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
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
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

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

type dummyIdentityUpdater struct{}

func (*dummyIdentityUpdater) UpdateIdentities(added, deleted identity.IdentityMap) <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}
