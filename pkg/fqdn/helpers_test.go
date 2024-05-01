// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/policy/api"
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
	var (
		ciliumIP1   = netip.MustParseAddr("1.2.3.4")
		ciliumIP2   = netip.MustParseAddr("1.2.3.5")
		nameManager = NewNameManager(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(0),
		})
	)

	log.Level = logrus.DebugLevel

	// Create DNS cache
	now := time.Now()
	cache := nameManager.cache

	selectors := sets.New[api.FQDNSelector](ciliumIOSel)

	// Empty cache.
	selIPMapping := nameManager.mapSelectorsToIPsLocked(selectors)
	require.Equal(t, 1, len(selIPMapping))
	ips, exists := selIPMapping[ciliumIOSel]
	require.Equal(t, true, exists)
	require.Equal(t, 0, len(ips))

	// Just one IP.
	changed := cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []netip.Addr{ciliumIP1}, 100)
	require.Equal(t, true, changed)
	selIPMapping = nameManager.mapSelectorsToIPsLocked(selectors)
	require.Equal(t, 1, len(selIPMapping))
	ciliumIPs, ok := selIPMapping[ciliumIOSel]
	require.Equal(t, true, ok)
	require.Equal(t, 1, len(ciliumIPs))
	require.Equal(t, ciliumIP1, ciliumIPs[0])

	// Two IPs now.
	changed = cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []netip.Addr{ciliumIP1, ciliumIP2}, 100)
	require.Equal(t, true, changed)
	selIPMapping = nameManager.mapSelectorsToIPsLocked(selectors)
	require.Equal(t, 1, len(selIPMapping))
	ciliumIPs, ok = selIPMapping[ciliumIOSel]
	require.Equal(t, true, ok)
	require.Equal(t, 2, len(ciliumIPs))
	ip.SortAddrList(ciliumIPs)
	require.Equal(t, ciliumIP1, ciliumIPs[0])
	require.Equal(t, ciliumIP2, ciliumIPs[1])

	// Test with a MatchPattern.
	selectors = sets.New(ciliumIOSelMatchPattern)

	selIPMapping = nameManager.mapSelectorsToIPsLocked(selectors)
	require.Equal(t, 1, len(selIPMapping))
	ciliumIPs, ok = selIPMapping[ciliumIOSelMatchPattern]
	require.Equal(t, true, ok)
	require.Equal(t, 2, len(ciliumIPs))
	ip.SortAddrList(ciliumIPs)
	require.Equal(t, ciliumIP1, ciliumIPs[0])
	require.Equal(t, ciliumIP2, ciliumIPs[1])

	selectors = sets.New(ciliumIOSelMatchPattern, ciliumIOSel)

	selIPMapping = nameManager.mapSelectorsToIPsLocked(selectors)
	require.Equal(t, 2, len(selIPMapping))
	ciliumIPs, ok = selIPMapping[ciliumIOSelMatchPattern]
	require.Equal(t, true, ok)
	require.Equal(t, 2, len(ciliumIPs))
	ip.SortAddrList(ciliumIPs)
	require.Equal(t, ciliumIP1, ciliumIPs[0])
	require.Equal(t, ciliumIP2, ciliumIPs[1])
	ciliumIPs, ok = selIPMapping[ciliumIOSel]
	require.Equal(t, true, ok)
	require.Equal(t, 2, len(ciliumIPs))
	ip.SortAddrList(ciliumIPs)
	require.Equal(t, ciliumIP1, ciliumIPs[0])
	require.Equal(t, ciliumIP2, ciliumIPs[1])
}
