// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package fqdn

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/checker"
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

func (ds *DNSCacheTestSuite) TestKeepUniqueNames(c *C) {
	r := rand.New(rand.NewSource(99))

	data := make([]string, 48)
	uniq := []string{}
	for i := 0; i < len(data); i++ {
		rnd := r.Float64()
		// Duplicate name with 10% probability
		if i > 0 && rnd < 0.1 {
			data[i] = data[int(float64(i-1)*r.Float64())]
		} else {
			data[i] = fmt.Sprintf("a%d.domain.com", i)
			uniq = append(uniq, data[i])
		}
	}

	testData := []struct {
		argument []string
		expected []string
	}{
		{[]string{"a"}, []string{"a"}},
		{[]string{"a", "a"}, []string{"a"}},
		{[]string{"a", "b"}, []string{"a", "b"}},
		{[]string{"a", "b", "b"}, []string{"a", "b"}},
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{[]string{"a", "b", "a", "c"}, []string{"a", "b", "c"}},
		{[]string{""}, []string{""}},
		{[]string{}, []string{}},
		{data, uniq},
	}

	for _, item := range testData {
		val := KeepUniqueNames(item.argument)
		c.Assert(val, checker.DeepEquals, item.expected)
	}
}

// Note: each "op" works on size things
func (ds *DNSCacheTestSuite) BenchmarkKeepUniqueNames(c *C) {
	c.StopTimer()
	data := make([]string, 48)
	for i := 0; i < len(data); i++ {
		data[i] = fmt.Sprintf("a%d.domain.com", i)
	}
	c.StartTimer()

	for i := 0; i < c.N; i++ {
		KeepUniqueNames(data)
	}
}

func (ds *DNSCacheTestSuite) TestMapIPsToSelectors(c *C) {

	var (
		ciliumIP1   = net.ParseIP("1.2.3.4")
		ciliumIP2   = net.ParseIP("1.2.3.5")
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
	changed := cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []net.IP{ciliumIP1}, 100)
	c.Assert(changed, Equals, true)
	selsMissingIPs, selIPMapping = nameManager.MapSelectorsToIPsLocked(selectors)
	c.Assert(len(selsMissingIPs), Equals, 0)
	c.Assert(len(selIPMapping), Equals, 1)
	ciliumIPs, ok := selIPMapping[ciliumIOSel]
	c.Assert(ok, Equals, true)
	c.Assert(len(ciliumIPs), Equals, 1)
	c.Assert(ciliumIPs[0].Equal(ciliumIP1), Equals, true)

	// Two IPs now.
	changed = cache.Update(now, prepareMatchName(ciliumIOSel.MatchName), []net.IP{ciliumIP1, ciliumIP2}, 100)
	c.Assert(changed, Equals, true)
	selsMissingIPs, selIPMapping = nameManager.MapSelectorsToIPsLocked(selectors)
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
	selsMissingIPs, selIPMapping = nameManager.MapSelectorsToIPsLocked(selectors)
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
	selsMissingIPs, selIPMapping = nameManager.MapSelectorsToIPsLocked(selectors)
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
