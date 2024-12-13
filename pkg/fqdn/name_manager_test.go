// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"
	"net/netip"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

type mockIPCache struct {
	metadata map[netip.Prefix]map[ipcacheTypes.ResourceID]labels.Labels
}

func newMockIPCache() *mockIPCache {
	return &mockIPCache{
		metadata: make(map[netip.Prefix]map[ipcacheTypes.ResourceID]labels.Labels),
	}
}

func (m *mockIPCache) labelsForPrefix(prefix netip.Prefix) labels.Labels {
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

func TestNameManagerIPCacheUpdates(t *testing.T) {
	ipc := newMockIPCache()
	nameManager := NewNameManager(Config{
		MinTTL:  1,
		Cache:   NewDNSCache(0),
		IPCache: ipc,
	})

	nameManager.RegisterFQDNSelector(ciliumIOSel)

	// Simulate lookup for single selector
	prefix := netip.MustParsePrefix("1.1.1.1/32")
	nameManager.UpdateGenerateDNS(context.TODO(), time.Now(), map[string]*DNSIPRecords{dns.FQDN("cilium.io"): {TTL: 60, IPs: []netip.Addr{prefix.Addr()}}})
	require.Equal(t, ipc.labelsForPrefix(prefix), labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel()}))

	// Add match pattern
	nameManager.RegisterFQDNSelector(ciliumIOSelMatchPattern)
	require.Equal(t, ipc.labelsForPrefix(prefix), labels.FromSlice([]labels.Label{ciliumIOSel.IdentityLabel(), ciliumIOSelMatchPattern.IdentityLabel()}))

	// Remove cilium.io matchname, add github.com match name
	nameManager.RegisterFQDNSelector(githubSel)
	nameManager.UnregisterFQDNSelector(ciliumIOSel)
	require.Equal(t, ipc.labelsForPrefix(prefix), labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel()}))

	// Same IP matched by two selectors
	nameManager.UpdateGenerateDNS(context.TODO(), time.Now(), map[string]*DNSIPRecords{dns.FQDN("github.com"): {TTL: 60, IPs: []netip.Addr{prefix.Addr()}}})
	require.Equal(t, ipc.labelsForPrefix(prefix), labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel(), githubSel.IdentityLabel()}))

	// Additional unique IPs for each selector
	githubPrefix := netip.MustParsePrefix("10.0.0.2/32")
	awesomePrefix := netip.MustParsePrefix("10.0.0.3/32")
	nameManager.UpdateGenerateDNS(context.TODO(), time.Now(), map[string]*DNSIPRecords{
		dns.FQDN("github.com"):       {TTL: 60, IPs: []netip.Addr{githubPrefix.Addr()}},
		dns.FQDN("awesomecilium.io"): {TTL: 60, IPs: []netip.Addr{awesomePrefix.Addr()}},
	})
	require.Equal(t, ipc.labelsForPrefix(prefix), labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel(), githubSel.IdentityLabel()}))
	require.Equal(t, ipc.labelsForPrefix(githubPrefix), labels.FromSlice([]labels.Label{githubSel.IdentityLabel()}))
	require.Equal(t, ipc.labelsForPrefix(awesomePrefix), labels.FromSlice([]labels.Label{ciliumIOSelMatchPattern.IdentityLabel()}))

	// Removing selector should remove from IPCache
	nameManager.UnregisterFQDNSelector(ciliumIOSelMatchPattern)
	require.NotContains(t, ipc.metadata, awesomePrefix)
	require.Equal(t, ipc.labelsForPrefix(prefix), labels.FromSlice([]labels.Label{githubSel.IdentityLabel()}))
	require.Equal(t, ipc.labelsForPrefix(githubPrefix), labels.FromSlice([]labels.Label{githubSel.IdentityLabel()}))
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
