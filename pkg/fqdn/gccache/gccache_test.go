// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gccache

import (
	"fmt"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
)

var cacheSize = 20

// // Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type FqdnGCCacheTestSuite struct{}

var _ = Suite(&FqdnGCCacheTestSuite{})

func (s *FqdnGCCacheTestSuite) SetUpSuite(c *C) {
	InitGCCache(cacheSize)
}

func (s *FqdnGCCacheTestSuite) TestAdd(c *C) {
	key := "example.com"
	Add(key)
	val, ok := Get(key)
	c.Assert(ok, Equals, true)
	_, err := time.Parse(time.RFC3339, val)
	c.Assert(err, Equals, nil)
}

func (s *FqdnGCCacheTestSuite) TestDump(c *C) {
	k1, k2 := "example.com", "example2.com"
	Add(k1, k2)

	val1, ok := Get(k1)
	c.Assert(ok, Equals, true)

	val2, ok := Get(k2)
	c.Assert(ok, Equals, true)

	want := []*models.FQDNGCCacheEntry{
		{Fqdn: k1, GarbageCollectionTime: val1},
		{Fqdn: k2, GarbageCollectionTime: val2},
	}
	got, err := Dump()
	c.Assert(err, Equals, nil)
	c.Assert(got, checker.DeepEquals, want)
}

// TestLRUCacheSize tests the size limit of the LRU cache, ensuring that the oldest
// entry is evicted once the cache reaches capacity.
func (s *FqdnGCCacheTestSuite) TestLRUCacheSize(c *C) {
	toEvict := "example.com"
	for i := 0; i < 20; i++ {
		Add(fmt.Sprintf("example%d.com", i))
	}

	_, ok := Get(toEvict)
	c.Assert(ok, Equals, false)
	c.Assert(Length(), Equals, cacheSize)
}
