// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"
	"fmt"
	"math"
	"path"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/testutils"
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

func (s *AllocatorSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

type AllocatorEtcdSuite struct {
	AllocatorSuite
}

var _ = Suite(&AllocatorEtcdSuite{})

func (e *AllocatorEtcdSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

func (e *AllocatorEtcdSuite) SetUpTest(c *C) {
	e.backend = "etcd"
	kvstore.SetupDummy("etcd")
}

func (e *AllocatorEtcdSuite) TearDownTest(c *C) {
	kvstore.Client().DeletePrefix(context.TODO(), testPrefix)
	kvstore.Client().Close(context.TODO())
}

type AllocatorConsulSuite struct {
	AllocatorSuite
}

var _ = Suite(&AllocatorConsulSuite{})

func (e *AllocatorConsulSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

func (e *AllocatorConsulSuite) SetUpTest(c *C) {
	e.backend = "consul"
	kvstore.SetupDummy("consul")
}

func (e *AllocatorConsulSuite) TearDownTest(c *C) {
	kvstore.Client().DeletePrefix(context.TODO(), testPrefix)
	kvstore.Client().Close(context.TODO())
}

// FIXME: this should be named better, it implements pkg/allocator.Backend
type TestAllocatorKey string

func (t TestAllocatorKey) GetKey() string { return string(t) }
func (t TestAllocatorKey) GetAsMap() map[string]string {
	return map[string]string{string(t): string(t)}
}
func (t TestAllocatorKey) String() string { return string(t) }
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
	return rand.RandomStringWithPrefix(testPrefix, 12)
}

func (s *AllocatorSuite) BenchmarkAllocate(c *C) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + c.N)
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID))
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))
	defer a.DeleteAllKeys()

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		_, _, _, err := a.Allocate(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
		c.Assert(err, IsNil)
	}
	c.StopTimer()

}

func (s *AllocatorSuite) TestRunLocksGC(c *C) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + c.N)
	// FIXME: Did this previousy use allocatorName := randomTestName() ? so TestAllocatorKey(randomeTestName())
	backend1, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)
	c.Assert(err, IsNil)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend1, allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	shortKey := TestAllocatorKey("1;")

	staleLocks := map[string]kvstore.Value{}
	staleLocks, err = allocator.RunLocksGC(context.Background(), staleLocks)
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
			client, _ = kvstore.NewClient(context.Background(),
				s.backend,
				map[string]string{
					kvstore.EtcdAddrOption: kvstore.EtcdDummyAddress(),
				},
				nil,
			)
		case "consul":
			client, _ = kvstore.NewClient(context.Background(),
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
	staleLocks, err = allocator.RunLocksGC(context.Background(), staleLocks)
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
		oldestRev     = uint64(math.MaxUint64)
		oldestLeaseID int64
		oldestKey     string
		sessionID     string
	)
	// Stale locks contains 2 locks, which is expected but we only want to GC
	// the oldest one so we can unlock all the remaining clients waiting to hold
	// the lock.
	for k, v := range staleLocks {
		if v.ModRevision < oldestRev {
			oldestKey = k
			oldestRev = v.ModRevision
			oldestLeaseID = v.LeaseID
			sessionID = v.SessionID
		}
	}

	// store the oldest key in the map so that it can be GCed.
	staleLocks = map[string]kvstore.Value{}
	staleLocks[oldestKey] = kvstore.Value{
		ModRevision: oldestRev,
		LeaseID:     oldestLeaseID,
		SessionID:   sessionID,
	}

	// GC lock1 because it's the oldest lock being held.
	staleLocks, err = allocator.RunLocksGC(context.Background(), staleLocks)
	c.Assert(err, IsNil)
	switch s.backend {
	case "consul":
		// Contrary to etcd, consul does not create a lock in the kvstore
		// if a lock is already being held. So we have GCed the only lock
		// available.
		c.Assert(len(staleLocks), Equals, 0)
	case "etcd":
		// There are 2 clients trying to get the lock, we have GC one of them
		// so that is way we have 1 staleLock in the map.
		c.Assert(len(staleLocks), Equals, 1)
	}

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
	err = lock1.Unlock(context.Background())
	c.Assert(err, IsNil)
	err = lock2.Unlock(context.Background())
	c.Assert(err, IsNil)
}

func (s *AllocatorSuite) TestGC(c *C) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + c.N)
	// FIXME: Did this previousy use allocatorName := randomTestName() ? so TestAllocatorKey(randomeTestName())
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))
	defer allocator.DeleteAllKeys()
	defer allocator.Delete()

	allocator.DeleteAllKeys()

	shortKey := TestAllocatorKey("1;")
	shortID, _, _, err := allocator.Allocate(context.Background(), shortKey)
	c.Assert(err, IsNil)
	c.Assert(shortID, Not(Equals), 0)

	longKey := TestAllocatorKey("1;2;")
	longID, _, _, err := allocator.Allocate(context.Background(), longKey)
	c.Assert(err, IsNil)
	c.Assert(longID, Not(Equals), 0)

	allocator.Release(context.Background(), shortKey)

	rateLimiter := rate.NewLimiter(10*time.Second, 100)

	keysToDelete := map[string]uint64{}
	keysToDelete, _, err = allocator.RunGC(rateLimiter, keysToDelete)
	c.Assert(err, IsNil)
	c.Assert(len(keysToDelete), Equals, 1)
	keysToDelete, _, err = allocator.RunGC(rateLimiter, keysToDelete)
	c.Assert(err, IsNil)
	c.Assert(len(keysToDelete), Equals, 0)

	// wait for cache to be updated via delete notification
	c.Assert(testutils.WaitUntil(func() bool {
		key, err := allocator.GetByID(context.TODO(), shortID)
		if err != nil {
			c.Error(err)
			return false
		}
		return key == nil
	}, 5*time.Second), IsNil)

	key, err := allocator.GetByID(context.TODO(), shortID)
	c.Assert(err, IsNil)
	c.Assert(key, IsNil)
}

func (s *AllocatorSuite) TestGC_ShouldSkipOutOfRangeIdentites(c *C) {

	// Allocator1: allocator under test
	backend, err := NewKVStoreBackend(randomTestName(), "a", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)

	maxID1 := idpool.ID(4 + c.N)
	allocator1, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID1), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator1, Not(IsNil))

	defer allocator1.DeleteAllKeys()
	defer allocator1.Delete()

	allocator1.DeleteAllKeys()

	shortKey1 := TestAllocatorKey("1;")
	shortID1, _, _, err := allocator1.Allocate(context.Background(), shortKey1)
	c.Assert(err, IsNil)
	c.Assert(shortID1, Not(Equals), 0)

	allocator1.Release(context.Background(), shortKey1)

	// Alloctor2: with a non-overlapping range compared with allocator1
	backend2, err := NewKVStoreBackend(randomTestName(), "a", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)

	minID2 := maxID1 + 1
	maxID2 := minID2 + 4
	allocator2, err := allocator.NewAllocator(TestAllocatorKey(""), backend2, allocator.WithMin(minID2), allocator.WithMax(maxID2), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator2, Not(IsNil))

	shortKey2 := TestAllocatorKey("2;")
	shortID2, _, _, err := allocator2.Allocate(context.Background(), shortKey2)
	c.Assert(err, IsNil)
	c.Assert(shortID2, Not(Equals), 0)

	defer allocator2.DeleteAllKeys()
	defer allocator2.Delete()

	allocator2.Release(context.Background(), shortKey2)

	// Perform GC with allocator1: there are two entries in kvstore currently
	rateLimiter := rate.NewLimiter(10*time.Second, 100)

	keysToDelete := map[string]uint64{}
	keysToDelete, _, err = allocator1.RunGC(rateLimiter, keysToDelete)
	c.Assert(err, IsNil)
	// But, only one will be filtered out and GC'ed
	c.Assert(len(keysToDelete), Equals, 1)
	keysToDelete, _, err = allocator1.RunGC(rateLimiter, keysToDelete)
	c.Assert(err, IsNil)
	c.Assert(len(keysToDelete), Equals, 0)

	// Wait for cache to be updated via delete notification
	c.Assert(testutils.WaitUntil(func() bool {
		key, err := allocator1.GetByID(context.TODO(), shortID1)
		if err != nil {
			c.Error(err)
			return false
		}
		return key == nil
	}, 5*time.Second), IsNil)

	// The key created with allocator1 should be GC'd
	key, err := allocator1.GetByID(context.TODO(), shortID1)
	c.Assert(err, IsNil)
	c.Assert(key, IsNil)

	// The key created with allocator2 should NOT be GC'd
	key2, err := allocator2.GetByID(context.TODO(), shortID2)
	c.Assert(err, IsNil)
	c.Assert(key2, Not(IsNil))
}

func testAllocator(c *C, maxID idpool.ID, allocatorName string, suffix string) {
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""), kvstore.Client())
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
		id, new, newLocally, err := a.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, true)
		c.Assert(newLocally, Equals, true)
	}

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, newLocally, err := a.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)
		c.Assert(newLocally, Equals, false)
	}

	// Create a 2nd allocator, refill it
	backend2, err := NewKVStoreBackend(allocatorName, "r", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)
	a2, err := allocator.NewAllocator(TestAllocatorKey(""), backend2,
		allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(a2, Not(IsNil))

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, newLocally, err := a2.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)
		c.Assert(newLocally, Equals, true)

		a2.Release(context.Background(), key)
	}

	// release 2nd reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		a.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
	}

	staleKeysPreviousRound := map[string]uint64{}
	rateLimiter := rate.NewLimiter(10*time.Second, 100)
	// running the GC should not evict any entries
	staleKeysPreviousRound, _, err = a.RunGC(rateLimiter, staleKeysPreviousRound)
	c.Assert(err, IsNil)

	v, err := kvstore.Client().ListPrefix(context.TODO(), path.Join(allocatorName, "id"))
	c.Assert(err, IsNil)
	c.Assert(len(v), Equals, int(maxID))

	// release final reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		a.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
	}

	// running the GC should evict all entries
	staleKeysPreviousRound, _, err = a.RunGC(rateLimiter, staleKeysPreviousRound)
	c.Assert(err, IsNil)
	_, _, err = a.RunGC(rateLimiter, staleKeysPreviousRound)
	c.Assert(err, IsNil)

	v, err = kvstore.Client().ListPrefix(context.TODO(), path.Join(allocatorName, "id"))
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
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""), kvstore.Client())
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
	backend, err := NewKVStoreBackend(allocatorName, "a", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID), allocator.WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()
	defer allocator.DeleteAllKeys()

	labelsLong := "foo;/;bar;"
	key := TestAllocatorKey(fmt.Sprintf("%s%010d", labelsLong, 0))
	longID, new, newLocally, err := allocator.Allocate(context.Background(), key)
	c.Assert(err, IsNil)
	c.Assert(longID, Not(Equals), 0)
	c.Assert(new, Equals, true)
	c.Assert(newLocally, Equals, true)

	observedID, err := allocator.GetNoCache(context.Background(), key)
	c.Assert(err, IsNil)
	c.Assert(observedID, Not(Equals), 0)

	labelsShort := "foo;/;"
	shortKey := TestAllocatorKey(labelsShort)
	observedID, err = allocator.GetNoCache(context.Background(), shortKey)
	c.Assert(err, IsNil)
	c.Assert(observedID, Equals, idpool.NoID)

	shortID, new, newLocally, err := allocator.Allocate(context.Background(), shortKey)
	c.Assert(err, IsNil)
	c.Assert(shortID, Not(Equals), 0)
	c.Assert(new, Equals, true)
	c.Assert(newLocally, Equals, true)

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
	backend, err := NewKVStoreBackend(testName, "a", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(idpool.ID(256)))
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))

	// remove any keys which might be leftover
	a.DeleteAllKeys()

	// allocate all available IDs
	for i := idpool.ID(1); i <= idpool.ID(4); i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		_, _, _, err := a.Allocate(context.Background(), key)
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
	backend2, err := NewKVStoreBackend(testName, "a", TestAllocatorKey(""), kvstore.Client())
	c.Assert(err, IsNil)
	a2, err := allocator.NewAllocator(TestAllocatorKey(""), backend2, allocator.WithMax(idpool.ID(256)))
	c.Assert(err, IsNil)
	rc := a.WatchRemoteKVStore("", a2)
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
