// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package fqdn

import (
	"net"
	"time"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
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
		ciliumIP1 = net.ParseIP("1.2.3.4")
		ciliumIP2 = net.ParseIP("1.2.3.5")
	)

	log.Level = logrus.DebugLevel

	// Create DNS cache
	now := time.Now()
	cache := NewDNSCache(60)

	selectors := map[api.FQDNSelector]struct{}{
		ciliumIOSel: {},
	}

	// Empty cache.
	selsMissingIPs, selIPMapping := mapSelectorsToIPs(selectors, cache)
	c.Assert(len(selsMissingIPs), Equals, 1)
	c.Assert(selsMissingIPs[0], Equals, ciliumIOSel)
	c.Assert(len(selIPMapping), Equals, 0)

	// Just one IP.
	changed := cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []net.IP{ciliumIP1}, 100)
	c.Assert(changed, Equals, true)
	selsMissingIPs, selIPMapping = mapSelectorsToIPs(selectors, cache)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok := selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 1)
	c.Assert(ciliumIPs[0].Equal(ciliumIP1), Equals, true)

	// Two IPs now.
	changed = cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []net.IP{ciliumIP1, ciliumIP2}, 100)
	c.Assert(changed, Equals, true)
	selsMissingIPs, selIPMapping = mapSelectorsToIPs(selectors, cache)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok = selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	c.Assert(ciliumIPs[0].Equal(ciliumIP1), Equals, true)
	c.Assert(ciliumIPs[1].Equal(ciliumIP2), Equals, true)

	// Test with a MatchPattern.
	selectors = map[api.FQDNSelector]struct{}{
		ciliumIOSelMatchPattern: {},
	}
	selsMissingIPs, selIPMapping = mapSelectorsToIPs(selectors, cache)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok = selIPMapping[ciliumIOSelMatchPattern]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	c.Assert(ciliumIPs[0].Equal(ciliumIP1), Equals, true)
	c.Assert(ciliumIPs[1].Equal(ciliumIP2), Equals, true)

	selectors = map[api.FQDNSelector]struct{}{
		ciliumIOSelMatchPattern: {},
		ciliumIOSel:             {},
	}
	selsMissingIPs, selIPMapping = mapSelectorsToIPs(selectors, cache)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 2)
	ciliumIPs, ok = selIPMapping[ciliumIOSelMatchPattern]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	c.Assert(ciliumIPs[0].Equal(ciliumIP1), Equals, true)
	c.Assert(ciliumIPs[1].Equal(ciliumIP2), Equals, true)
	ciliumIPs, ok = selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 2)
	c.Assert(ciliumIPs[0].Equal(ciliumIP1), Equals, true)
	c.Assert(ciliumIPs[1].Equal(ciliumIP2), Equals, true)
}
