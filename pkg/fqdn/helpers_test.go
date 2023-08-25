// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net/netip"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/sirupsen/logrus"

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

	selectors := map[api.FQDNSelector]struct{}{
		ciliumIOSel: {},
	}

	// Empty cache.
	selsMissingIPs, selIPMapping := nameManager.MapSelectorsToIPsLocked(selectors)
	c.Assert(len(selsMissingIPs), Equals, 1)
	c.Assert(selsMissingIPs[0], Equals, ciliumIOSel)
	c.Assert(len(selIPMapping), Equals, 0)

	// Just one IP.
	changed := cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []netip.Addr{ciliumIP1}, 100)
	c.Assert(changed, Equals, true)
	selsMissingIPs, selIPMapping = nameManager.MapSelectorsToIPsLocked(selectors)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok := selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 1)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[0]), Equals, ciliumIP1)

	// Two IPs now.
	changed = cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []netip.Addr{ciliumIP1, ciliumIP2}, 100)
	c.Assert(changed, Equals, true)
	selsMissingIPs, selIPMapping = nameManager.MapSelectorsToIPsLocked(selectors)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok = selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[0]), Equals, ciliumIP1)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[1]), Equals, ciliumIP2)

	// Test with a MatchPattern.
	selectors = map[api.FQDNSelector]struct{}{
		ciliumIOSelMatchPattern: {},
	}
	selsMissingIPs, selIPMapping = nameManager.MapSelectorsToIPsLocked(selectors)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok = selIPMapping[ciliumIOSelMatchPattern]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[0]), Equals, ciliumIP1)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[1]), Equals, ciliumIP2)

	selectors = map[api.FQDNSelector]struct{}{
		ciliumIOSelMatchPattern: {},
		ciliumIOSel:             {},
	}
	selsMissingIPs, selIPMapping = nameManager.MapSelectorsToIPsLocked(selectors)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 2)
	ciliumIPs, ok = selIPMapping[ciliumIOSelMatchPattern]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[0]), Equals, ciliumIP1)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[1]), Equals, ciliumIP2)
	ciliumIPs, ok = selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[0]), Equals, ciliumIP1)
	c.Assert(ip.MustAddrFromIP(ciliumIPs[1]), Equals, ciliumIP2)
}
