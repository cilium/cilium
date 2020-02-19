// Copyright 2016-2020 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/allocator"
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

type AllocatorSuite struct {
	backend string
}

type AllocatorEtcdSuite struct {
	AllocatorSuite
}

var _ = Suite(&AllocatorEtcdSuite{})

func (e *AllocatorEtcdSuite) SetUpTest(c *C) {
	e.backend = "etcd"
	kvstore.SetupDummy("etcd")
}

func (e *AllocatorEtcdSuite) TearDownTest(c *C) {
	kvstore.Client().DeletePrefix(testPrefix)
	kvstore.Client().Close()
}

type AllocatorConsulSuite struct {
	AllocatorSuite
}

var _ = Suite(&AllocatorConsulSuite{})

func (e *AllocatorConsulSuite) SetUpTest(c *C) {
	e.backend = "consul"
	kvstore.SetupDummy("consul")
}

func (e *AllocatorConsulSuite) TearDownTest(c *C) {
	kvstore.Client().DeletePrefix(testPrefix)
	kvstore.Client().Close()
}

//FIXME: this should be named better, it implements pkg/allocator.Backend
type TestAllocatorKey string

func (t TestAllocatorKey) GetKey() string              { return string(t) }
func (t TestAllocatorKey) GetAsMap() map[string]string { return map[string]string{string(t): string(t)} }
func (t TestAllocatorKey) String() string              { return string(t) }
func (t TestAllocatorKey) PutKey(v string) allocator.AllocatorKey {
	return TestAllocatorKey(v)
}
func (t TestAllocatorKey) PutKeyFromMap(m map[string]string) allocator.AllocatorKey {
	for _, v := range m {
		return TestAllocatorKey(v)
	}

	panic("empty map")
}

func randomTestName() string {
	return testutils.RandomRuneWithPrefix(testPrefix, 12)
}

func (s *AllocatorSuite) BenchmarkAllocate(c *C) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + c.N)
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""))
	c.Assert(err, IsNil)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID))
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))
	defer a.DeleteAllKeys()

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		_, _, err := a.Allocate(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
		c.Assert(err, IsNil)
	}
	c.StopTimer()

}

func (s *AllocatorSuite) TestRunLocksGC(c *C) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + c.N)
	// FIXME: Did this previousy use allocatorName := randomTestName() ? so TestAllocatorKey(randomeTestName())
	backend1, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""))
	c.Assert(err, IsNil)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend1, allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	shortKey := TestAllocatorKey("1;")

	staleLocks := map[string]kvstore.Value{}
	staleLocks, err = allocator.RunLocksGC(staleLocks)
	c.Assert(err, IsNil)
	c.Assert(len(staleLocks), Equals, 0)

	var (
		lock1, lock2 kvstore.KVLocker
		gotLock1     = make(chan struct{})
		gotLock2     = make(chan struct{})
	)
	go func() {
		var (
			err error
		)
		lock1, err = backend1.Lock(context.Background(), shortKey)
		c.Assert(err, IsNil)
		close(gotLock1)
		var client kvstore.BackendOperations
		switch s.backend {
		case "etcd":
			client, _ = kvstore.NewClient(
				s.backend,
				map[string]string{
					kvstore.EtcdAddrOption: kvstore.EtcdDummyAddress(),
				},
				nil,
			)
		case "consul":
			client, _ = kvstore.NewClient(
				s.backend,
				map[string]string{
					kvstore.ConsulAddrOption:   kvstore.ConsulDummyAddress(),
					kvstore.ConsulOptionConfig: kvstore.ConsulDummyConfigFile(),
				},
				nil,
			)
		}
		lock2, err = client.LockPath(context.Background(), allocatorName+"/locks/"+kvstore.Client().Encode([]byte(shortKey.GetKey())))
		c.Assert(err, IsNil)
		close(gotLock2)
	}()

	// Wait until lock1 is gotten.
	c.Assert(testutils.WaitUntil(func() bool {
		select {
		case <-gotLock1:
			return true
		default:
			return false
		}
	}, 5*time.Second), IsNil)

	// wait until client2, in line 160, tries to grab the lock.
	// We can't detect when that actually happen so we have to assume it will
	// happen within one second.
	time.Sleep(time.Second)

	// Check which locks are stale, it should be lock1 and lock2
	staleLocks, err = allocator.RunLocksGC(staleLocks)
	c.Assert(err, IsNil)
	switch s.backend {
	case "consul":
		// Contrary to etcd, consul does not create a lock in the kvstore
		// if a lock is already being held.
		c.Assert(len(staleLocks), Equals, 1)
	case "etcd":
		c.Assert(len(staleLocks), Equals, 2)
	}

	var (
		oldestRev     uint64
		oldestLeaseID int64
		sessionID     string
	)
	// Stale locks contains 2 locks, which is expected but we only want to GC
	// the oldest one so we can unlock all the remaining clients waiting to hold
	// the lock.
	for _, v := range staleLocks {
		if v.ModRevision < oldestRev {
			oldestRev = v.ModRevision
			oldestLeaseID = v.LeaseID
			sessionID = v.SessionID
		}
	}
	staleLocks[allocatorName+"/locks/"+shortKey.GetKey()] = kvstore.Value{
		ModRevision: oldestRev,
		LeaseID:     oldestLeaseID,
		SessionID:   sessionID,
	}

	// GC lock1 because it's the oldest lock being held.
	staleLocks, err = allocator.RunLocksGC(staleLocks)
	c.Assert(err, IsNil)
	c.Assert(len(staleLocks), Equals, 0)

	// Wait until lock2 is gotten as it should have happen since we have
	// GC lock1.
	c.Assert(testutils.WaitUntil(func() bool {
		select {
		case <-gotLock2:
			return true
		default:
			return false
		}
	}, 10*time.Second), IsNil)

	// Unlock lock1 because we still hold the local locks.
	err = lock1.Unlock()
	c.Assert(err, IsNil)
	err = lock2.Unlock()
	c.Assert(err, IsNil)
}

func (s *AllocatorSuite) TestGC(c *C) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + c.N)
	// FIXME: Did this previousy use allocatorName := randomTestName() ? so TestAllocatorKey(randomeTestName())
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""))
	c.Assert(err, IsNil)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))
	defer allocator.DeleteAllKeys()
	defer allocator.Delete()

	allocator.DeleteAllKeys()

	shortKey := TestAllocatorKey("1;")
	shortID, _, err := allocator.Allocate(context.Background(), shortKey)
	c.Assert(err, IsNil)
	c.Assert(shortID, Not(Equals), 0)

	longKey := TestAllocatorKey("1;2;")
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
	c.Assert(testutils.WaitUntil(func() bool {
		key, err := allocator.GetByID(shortID)
		if err != nil {
			c.Error(err)
			return false
		}
		//FIXME: This isn't nil but it probably should be. This is because TestAllocatorKey is setup with "" and returns itself, a non-nil
		return key == nil || key.String() == ""
	}, 5*time.Second), IsNil)

	key, err := allocator.GetByID(shortID)
	c.Assert(err, IsNil)
	c.Assert(key, Equals, TestAllocatorKey(""))
}

func testAllocator(c *C, maxID idpool.ID, allocatorName string, suffix string) {
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""))
	c.Assert(err, IsNil)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend,
		allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))

	// remove any keys which might be leftover
	a.DeleteAllKeys()

	// allocate all available IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, err := a.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, true)
	}

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, err := a.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)
	}

	// Create a 2nd allocator, refill it
	backend2, err := NewKVStoreBackend(allocatorName, "r", TestAllocatorKey(""))
	c.Assert(err, IsNil)
	a2, err := allocator.NewAllocator(TestAllocatorKey(""), backend2,
		allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(a2, Not(IsNil))

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, err := a2.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)

		a2.Release(context.Background(), key)
	}

	// release 2nd reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		a.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
	}

	staleKeysPreviousRound := map[string]uint64{}
	// running the GC should not evict any entries
	staleKeysPreviousRound, err = a.RunGC(staleKeysPreviousRound)
	c.Assert(err, IsNil)

	v, err := kvstore.Client().ListPrefix(path.Join(allocatorName, "id"))
	c.Assert(err, IsNil)
	c.Assert(len(v), Equals, int(maxID))

	// release final reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		a.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
	}

	// running the GC should evict all entries
	staleKeysPreviousRound, err = a.RunGC(staleKeysPreviousRound)
	c.Assert(err, IsNil)
	_, err = a.RunGC(staleKeysPreviousRound)
	c.Assert(err, IsNil)

	v, err = kvstore.Client().ListPrefix(path.Join(allocatorName, "id"))
	c.Assert(err, IsNil)
	c.Assert(len(v), Equals, 0)

	a.DeleteAllKeys()
	a.Delete()
	a2.Delete()
}

func (s *AllocatorSuite) TestAllocateCached(c *C) {
	testAllocator(c, idpool.ID(32), randomTestName(), "a") // enable use of local cache
}

func (s *AllocatorSuite) TestKeyToID(c *C) {
	allocatorName := randomTestName()
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""))
	c.Assert(err, IsNil)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend)
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

func testGetNoCache(c *C, maxID idpool.ID, suffix string) {
	allocatorName := randomTestName()
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""))
	c.Assert(err, IsNil)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()
	defer allocator.DeleteAllKeys()

	labelsLong := "foo;/;bar;"
	key := TestAllocatorKey(fmt.Sprintf("%s%010d", labelsLong, 0))
	longID, new, err := allocator.Allocate(context.Background(), key)
	c.Assert(err, IsNil)
	c.Assert(longID, Not(Equals), 0)
	c.Assert(new, Equals, true)

	observedID, err := allocator.GetNoCache(context.Background(), key)
	c.Assert(err, IsNil)
	c.Assert(observedID, Not(Equals), 0)

	labelsShort := "foo;/;"
	shortKey := TestAllocatorKey(labelsShort)
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
	testGetNoCache(c, idpool.ID(256), "a") // enable use of local cache
}

func (s *AllocatorSuite) TestRemoteCache(c *C) {
	testName := randomTestName()
	backend, err := NewKVStoreBackend(testName, "a", TestAllocatorKey(""))
	c.Assert(err, IsNil)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(idpool.ID(256)))
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))

	// remove any keys which might be leftover
	a.DeleteAllKeys()

	// allocate all available IDs
	for i := idpool.ID(1); i <= idpool.ID(4); i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		_, _, err := a.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
	}

	// wait for main cache to be populated
	c.Assert(testutils.WaitUntil(func() bool {
		cacheLen := 0
		a.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
			cacheLen++
		})
		return cacheLen == 4
	}, 5*time.Second), IsNil)

	// count identical allocations returned
	cache := map[idpool.ID]int{}
	a.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
		cache[id]++
	})

	// ForeachCache must have returned 4 allocations all unique
	c.Assert(len(cache), Equals, 4)
	for i := range cache {
		c.Assert(cache[i], Equals, 1)
	}

	// watch the prefix in the same kvstore via a 2nd watcher
	rc := a.WatchRemoteKVStore(kvstore.Client(), testName)
	c.Assert(rc, Not(IsNil))

	// wait for remote cache to be populated
	c.Assert(testutils.WaitUntil(func() bool {
		cacheLen := 0
		a.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
			cacheLen++
		})
		// 4 local + 4 remote
		return cacheLen == 8
	}, 5*time.Second), IsNil)

	// count the allocations in the main cache *AND* the remote cache
	cache = map[idpool.ID]int{}
	a.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
		cache[id]++
	})

	// Foreach must have returned 4 allocations each duplicated, once in
	// the main cache, once in the remote cache
	c.Assert(len(cache), Equals, 4)
	for i := range cache {
		c.Assert(cache[i], Equals, 2)
	}

	rc.Close()

	a.DeleteAllKeys()
	a.Delete()
}
