// Copyright 2016-2019 Authors of Cilium
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

package allocator

import (
	"context"
	"fmt"
	"path"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

const (
	testPrefix = "test-prefix"
)

func Test(t *testing.T) {
	TestingT(t)
}

type AllocatorSuite struct{}

type AllocatorEtcdSuite struct {
	AllocatorSuite
}

var _ = Suite(&AllocatorEtcdSuite{})

func (e *AllocatorEtcdSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")
}

func (e *AllocatorEtcdSuite) TearDownTest(c *C) {
	kvstore.DeletePrefix(testPrefix)
	kvstore.Close()
}

type AllocatorConsulSuite struct {
	AllocatorSuite
}

var _ = Suite(&AllocatorConsulSuite{})

func (e *AllocatorConsulSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("consul")
}

func (e *AllocatorConsulSuite) TearDownTest(c *C) {
	kvstore.DeletePrefix(testPrefix)
	kvstore.Close()
}

type TestType string

func (t TestType) GetKey() string { return string(t) }
func (t TestType) String() string { return string(t) }
func (t TestType) PutKey(v string) (AllocatorKey, error) {
	return TestType(v), nil
}

func randomTestName() string {
	return testutils.RandomRuneWithPrefix(testPrefix, 12)
}

func (s *AllocatorSuite) TestSelectID(c *C) {
	allocatorName := randomTestName()
	minID, maxID := idpool.ID(1), idpool.ID(5)
	a, err := NewAllocator(allocatorName, TestType(""), WithMin(minID), WithMax(maxID), WithSuffix("a"))
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))

	// allocate all available IDs
	for i := minID; i <= maxID; i++ {
		id, val, unmaskedID := a.selectAvailableID()
		c.Assert(id, Not(Equals), idpool.NoID)
		c.Assert(val, Equals, id.String())
		c.Assert(id, Equals, unmaskedID)
		a.mainCache.cache[id] = TestType(fmt.Sprintf("key-%d", i))
	}

	// we should be out of IDs
	id, val, unmaskedID := a.selectAvailableID()
	c.Assert(id, Equals, idpool.ID(0))
	c.Assert(id, Equals, unmaskedID)
	c.Assert(val, Equals, "")
}

func (s *AllocatorSuite) TestPrefixMask(c *C) {
	allocatorName := randomTestName()
	minID, maxID := idpool.ID(1), idpool.ID(5)
	a, err := NewAllocator(allocatorName, TestType(""), WithMin(minID),
		WithMax(maxID), WithSuffix("a"), WithPrefixMask(1<<16))
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))

	// allocate all available IDs
	for i := minID; i <= maxID; i++ {
		id, val, unmaskedID := a.selectAvailableID()
		c.Assert(id, Not(Equals), idpool.NoID)
		c.Assert(id>>16, Equals, idpool.ID(1))
		c.Assert(id, Not(Equals), unmaskedID)
		c.Assert(val, Equals, id.String())
	}

	a.Delete()
}

func (s *AllocatorSuite) BenchmarkAllocate(c *C) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + c.N)
	allocator, err := NewAllocator(allocatorName, TestType(""), WithMax(maxID), WithSuffix("a"))
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))
	defer allocator.DeleteAllKeys()

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		_, _, err := allocator.Allocate(context.Background(), TestType(fmt.Sprintf("key%04d", i)))
		c.Assert(err, IsNil)
	}
	c.StopTimer()

}

func (s *AllocatorSuite) TestGC(c *C) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + c.N)
	allocator, err := NewAllocator(allocatorName, TestType(""), WithMax(maxID), WithSuffix("a"), WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))
	defer allocator.DeleteAllKeys()
	defer allocator.Delete()

	allocator.DeleteAllKeys()

	shortKey := TestType("1;")
	shortID, _, err := allocator.Allocate(context.Background(), shortKey)
	c.Assert(err, IsNil)
	c.Assert(shortID, Not(Equals), 0)

	longKey := TestType("1;2;")
	longID, _, err := allocator.Allocate(context.Background(), longKey)
	c.Assert(err, IsNil)
	c.Assert(longID, Not(Equals), 0)

	allocator.Release(context.Background(), shortKey)

	keysToDelete := map[string]uint64{}
	keysToDelete, err = allocator.RunGC(keysToDelete)
	c.Assert(err, IsNil)
	c.Assert(len(keysToDelete), Equals, 1)
	keysToDelete, err = allocator.RunGC(keysToDelete)
	c.Assert(err, IsNil)
	c.Assert(len(keysToDelete), Equals, 0)

	// wait for cache to be updated via delete notification
	c.Assert(testutils.WaitUntil(func() bool { return allocator.mainCache.getByID(shortID) == nil }, 5*time.Second), IsNil)

	key, err := allocator.GetByID(shortID)
	c.Assert(err, IsNil)
	c.Assert(key, Equals, TestType(""))
}

func testAllocator(c *C, maxID idpool.ID, allocatorName string, suffix string) {
	allocator, err := NewAllocator(allocatorName, TestType(""), WithMax(maxID),
		WithSuffix(suffix), WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()

	// allocate all available IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		id, new, err := allocator.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, true)

		// refcnt must be 1
		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(1))
	}

	saved := allocator.backoffTemplate.Factor
	allocator.backoffTemplate.Factor = 1.0

	// we should be out of id space here
	_, new, err := allocator.Allocate(context.Background(), TestType(fmt.Sprintf("key%04d", maxID+1)))
	c.Assert(err, Not(IsNil))
	c.Assert(new, Equals, false)

	allocator.backoffTemplate.Factor = saved

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		id, new, err := allocator.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)

		// refcnt must now be 2
		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(2))
	}

	// Create a 2nd allocator, refill it
	allocator2, err := NewAllocator(allocatorName, TestType(""), WithMax(maxID),
		WithSuffix("b"), WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator2, Not(IsNil))

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		id, new, err := allocator2.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)

		localKey := allocator2.localKeys.keys[key.GetKey()]
		c.Assert(localKey, Not(IsNil))

		// refcnt in the 2nd allocator is 1
		c.Assert(localKey.refcnt, Equals, uint64(1))

		allocator2.Release(context.Background(), key)
	}

	// release 2nd reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		allocator.Release(context.Background(), TestType(fmt.Sprintf("key%04d", i)))
	}

	// refcnt should be back to 1
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(1))
	}

	keysToDelete := map[string]uint64{}
	// running the GC should not evict any entries
	keysToDelete, err = allocator.RunGC(keysToDelete)
	c.Assert(err, IsNil)
	c.Assert(len(keysToDelete), Equals, 0)

	v, err := kvstore.ListPrefix(allocator.idPrefix)
	c.Assert(err, IsNil)
	c.Assert(len(v), Equals, int(maxID))

	// release final reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		allocator.Release(context.Background(), TestType(fmt.Sprintf("key%04d", i)))
	}

	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		c.Assert(allocator.localKeys.keys[key.GetKey()], IsNil)
	}

	// running the GC should evict all entries
	keysToDelete, err = allocator.RunGC(keysToDelete)
	c.Assert(err, IsNil)
	c.Assert(len(keysToDelete), Equals, int(maxID))
	keysToDelete, err = allocator.RunGC(keysToDelete)
	c.Assert(err, IsNil)
	c.Assert(len(keysToDelete), Equals, 0)

	v, err = kvstore.ListPrefix(allocator.idPrefix)
	c.Assert(err, IsNil)
	c.Assert(len(v), Equals, 0)

	allocator.DeleteAllKeys()
	allocator.Delete()
	allocator2.Delete()
}

func (s *AllocatorSuite) TestAllocateCached(c *C) {
	testAllocator(c, idpool.ID(32), randomTestName(), "a") // enable use of local cache
}

func (s *AllocatorSuite) TestKeyToID(c *C) {
	allocatorName := randomTestName()
	a, err := NewAllocator(allocatorName, TestType(""), WithSuffix("a"))
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))

	// An error is returned because the path is outside the prefix (allocatorName/id)
	id, err := backend.keyToID(path.Join(allocatorName, "invalid"))
	c.Assert(err, Not(IsNil))
	c.Assert(id, Equals, idpool.NoID)

	// An error is returned because the path contains the prefix
	// (allocatorName/id) but cannot be parsed ("invalid")
	id, err = backend.keyToID(path.Join(allocatorName, "id", "invalid"))
	c.Assert(err, Not(IsNil))
	c.Assert(id, Equals, idpool.NoID)

	// A valid lookup that finds an ID
	id, err = backend.keyToID(path.Join(allocatorName, "id", "10"))
	c.Assert(err, IsNil)
	c.Assert(id, Equals, idpool.ID(10))
}

func testGetNoCache(c *C, maxID idpool.ID, testName string, suffix string) {
	allocator, err := NewAllocator(testName, TestType(""), WithMax(maxID),
		WithSuffix(suffix), WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()
	defer allocator.DeleteAllKeys()

	labelsLong := "foo;/;bar;"
	key := TestType(fmt.Sprintf("%s%010d", labelsLong, 0))
	longID, new, err := allocator.Allocate(context.Background(), key)
	c.Assert(err, IsNil)
	c.Assert(longID, Not(Equals), 0)
	c.Assert(new, Equals, true)

	observedID, err := allocator.GetNoCache(context.Background(), key)
	c.Assert(err, IsNil)
	c.Assert(observedID, Not(Equals), 0)

	labelsShort := "foo;/;"
	shortKey := TestType(labelsShort)
	observedID, err = allocator.GetNoCache(context.Background(), shortKey)
	c.Assert(err, IsNil)
	c.Assert(observedID, Equals, idpool.NoID)

	shortID, new, err := allocator.Allocate(context.Background(), shortKey)
	c.Assert(err, IsNil)
	c.Assert(shortID, Not(Equals), 0)
	c.Assert(new, Equals, true)

	observedID, err = allocator.GetNoCache(context.Background(), shortKey)
	c.Assert(err, IsNil)
	c.Assert(observedID, Equals, shortID)
}

func (s *AllocatorSuite) TestprefixMatchesKey(c *C) {
	// cilium/state/identities/v1/value/label;foo;bar;/172.0.124.60

	tests := []struct {
		prefix   string
		key      string
		expected bool
	}{
		{
			prefix:   "foo",
			key:      "foo/bar",
			expected: true,
		},
		{
			prefix:   "foo/;bar;baz;/;a;",
			key:      "foo/;bar;baz;/;a;/alice",
			expected: true,
		},
		{
			prefix:   "foo/;bar;baz;",
			key:      "foo/;bar;baz;/;a;/alice",
			expected: false,
		},
		{
			prefix:   "foo/;bar;baz;/;a;/baz",
			key:      "foo/;bar;baz;/;a;/alice",
			expected: false,
		},
	}

	for _, tt := range tests {
		c.Logf("prefixMatchesKey(%q, %q) expected to be %t", tt.prefix, tt.key, tt.expected)
		result := prefixMatchesKey(tt.prefix, tt.key)
		c.Assert(result, Equals, tt.expected)
	}
}

func (s *AllocatorSuite) TestGetNoCache(c *C) {
	testGetNoCache(c, idpool.ID(256), randomTestName(), "a") // enable use of local cache
}

func (s *AllocatorSuite) TestRemoteCache(c *C) {
	testName := randomTestName()
	allocator, err := NewAllocator(testName, TestType(""), WithMax(idpool.ID(256)), WithSuffix("a"))
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()

	// allocate all available IDs
	for i := idpool.ID(1); i <= idpool.ID(4); i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		_, _, err := allocator.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
	}

	// wait for main cache to be populated
	c.Assert(testutils.WaitUntil(func() bool { return len(allocator.mainCache.cache) == 4 }, 5*time.Second), IsNil)

	// count identical allocations returned
	cache := map[idpool.ID]int{}
	allocator.ForeachCache(func(id idpool.ID, val AllocatorKey) {
		cache[id]++
	})

	// ForeachCache must have returned 4 allocations all unique
	c.Assert(len(cache), Equals, 4)
	for i := range cache {
		c.Assert(cache[i], Equals, 1)
	}

	// watch the prefix in the same kvstore via a 2nd watcher
	rc := allocator.WatchRemoteKVStore(kvstore.Client(), testName)
	c.Assert(rc, Not(IsNil))

	// wait for remote cache to be populated
	c.Assert(testutils.WaitUntil(func() bool { return len(rc.cache.cache) == 4 }, 5*time.Second), IsNil)

	// count the allocations in the main cache *AND* the remote cache
	cache = map[idpool.ID]int{}
	allocator.ForeachCache(func(id idpool.ID, val AllocatorKey) {
		cache[id]++
	})

	// Foreach must have returned 4 allocations each duplicated, once in
	// the main cache, once in the remote cache
	c.Assert(len(cache), Equals, 4)
	for i := range cache {
		c.Assert(cache[i], Equals, 2)
	}

	rc.Close()

	allocator.DeleteAllKeys()
	allocator.Delete()
}

// The following tests are currently disabled as they are not 100% reliable in
// the Jenkins CI
//
//func testParallelAllocator(c *C, maxID idpool.ID, allocatorName string, suffix string) {
//	allocator, err := NewAllocator(allocatorName, TestType(""), WithMax(maxID), WithSuffix(suffix))
//	c.Assert(err, IsNil)
//	c.Assert(allocator, Not(IsNil))
//
//	// allocate all available IDs
//	for i := idpool.ID(1); i <= maxID; i++ {
//		key := TestType(fmt.Sprintf("key%04d", i))
//		id, _, err := allocator.Allocate(context.Background(), key)
//		c.Assert(err, IsNil)
//		c.Assert(id, Not(Equals), 0)
//
//		// refcnt must be 1
//		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(1))
//	}
//
//	saved := allocator.backoffTemplate.Factor
//	allocator.backoffTemplate.Factor = 1.0
//
//	// we should be out of id space here
//	_, new, err := allocator.Allocate(context.Background(), TestType(fmt.Sprintf("key%04d", maxID+1)))
//	c.Assert(err, Not(IsNil))
//	c.Assert(new, Equals, false)
//
//	allocator.backoffTemplate.Factor = saved
//
//	// allocate all IDs again using the same set of keys, refcnt should go to 2
//	for i := idpool.ID(1); i <= maxID; i++ {
//		key := TestType(fmt.Sprintf("key%04d", i))
//		id, _, err := allocator.Allocate(context.Background(), key)
//		c.Assert(err, IsNil)
//		c.Assert(id, Not(Equals), 0)
//
//		// refcnt must now be 2
//		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(2))
//	}
//
//	for i := idpool.ID(1); i <= maxID; i++ {
//		allocator.Release(context.Background(), TestType(fmt.Sprintf("key%04d", i)))
//	}
//
//	// release final reference of all IDs
//	for i := idpool.ID(1); i <= maxID; i++ {
//		allocator.Release(context.Background(), TestType(fmt.Sprintf("key%04d", i)))
//	}
//
//	// running the GC should evict all entries
//	allocator.RunGC()
//
//	v, err := kvstore.ListPrefix(allocator.idPrefix)
//	c.Assert(err, IsNil)
//	c.Assert(len(v), Equals, 0)
//
//	allocator.Delete()
//}
//
//func (s *AllocatorSuite) TestParallelAllocation(c *C) {
//	var (
//		wg            sync.WaitGroup
//		allocatorName = randomTestName()
//	)
//
//	// create dummy allocator to delete all keys
//	a, err := NewAllocator(allocatorName, TestType(""), WithSuffix("a"))
//	c.Assert(err, IsNil)
//	c.Assert(a, Not(IsNil))
//	defer a.DeleteAllKeys()
//	defer a.Delete()
//
//	for i := 0; i < 2; i++ {
//		wg.Add(1)
//		go func() {
//			defer wg.Done()
//			testParallelAllocator(c, idpool.ID(64), allocatorName, fmt.Sprintf("node-%d", i))
//		}()
//	}
//
//	wg.Wait()
//}
