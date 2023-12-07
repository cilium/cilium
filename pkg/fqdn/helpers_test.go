// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net/netip"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/sirupsen/logrus"
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

func (ds *DNSCacheTestSuite) TestMapIPsToSelectors(c *C) {
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
	c.Assert(len(selIPMapping), Equals, 1)
	ips, exists := selIPMapping[ciliumIOSel]
	c.Assert(exists, Equals, true)
	c.Assert(len(ips), Equals, 0)

	// Just one IP.
	changed := cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []netip.Addr{ciliumIP1}, 100)
	c.Assert(changed, Equals, true)
	selIPMapping = nameManager.mapSelectorsToIPsLocked(selectors)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok := selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 1)
	c.Assert(ciliumIPs[0], Equals, ciliumIP1)

	// Two IPs now.
	changed = cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []netip.Addr{ciliumIP1, ciliumIP2}, 100)
	c.Assert(changed, Equals, true)
	selIPMapping = nameManager.mapSelectorsToIPsLocked(selectors)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok = selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	ip.SortAddrList(ciliumIPs)
	c.Assert(ciliumIPs[0], Equals, ciliumIP1)
	c.Assert(ciliumIPs[1], Equals, ciliumIP2)

	// Test with a MatchPattern.
	selectors = sets.New(ciliumIOSelMatchPattern)

	selIPMapping = nameManager.mapSelectorsToIPsLocked(selectors)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok = selIPMapping[ciliumIOSelMatchPattern]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	ip.SortAddrList(ciliumIPs)
	c.Assert(ciliumIPs[0], Equals, ciliumIP1)
	c.Assert(ciliumIPs[1], Equals, ciliumIP2)

	selectors = sets.New(ciliumIOSelMatchPattern, ciliumIOSel)

	selIPMapping = nameManager.mapSelectorsToIPsLocked(selectors)
	c.Assert(len(selIPMapping), Equals, 2)
	ciliumIPs, ok = selIPMapping[ciliumIOSelMatchPattern]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	ip.SortAddrList(ciliumIPs)
	c.Assert(ciliumIPs[0], Equals, ciliumIP1)
	c.Assert(ciliumIPs[1], Equals, ciliumIP2)
	ciliumIPs, ok = selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	ip.SortAddrList(ciliumIPs)
	c.Assert(ciliumIPs[0], Equals, ciliumIP1)
	c.Assert(ciliumIPs[1], Equals, ciliumIP2)
}
