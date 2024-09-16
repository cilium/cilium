// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"
	"fmt"
	"math"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	testPrefix = "test-prefix"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second

	etcdOpts = map[string]string{kvstore.EtcdRateLimitOption: "100"}
)

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

func (t TestAllocatorKey) PutValue(key any, value any) allocator.AllocatorKey {
	panic("not implemented")
}

func (t TestAllocatorKey) Value(any) any {
	panic("not implemented")
}

func randomTestName() string {
	return fmt.Sprintf("%s%s", testPrefix, rand.String(12))
}

func BenchmarkAllocate(b *testing.B) {
	testutils.IntegrationTest(b)
	kvstore.SetupDummyWithConfigOpts(b, "etcd", etcdOpts)
	benchmarkAllocate(b)
}

func benchmarkAllocate(b *testing.B) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + b.N)
	backend, err := NewKVStoreBackend(KVStoreBackendConfiguration{allocatorName, "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(b, err)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID))
	require.NoError(b, err)
	require.NotNil(b, a)
	defer a.DeleteAllKeys()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := a.Allocate(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
		require.NoError(b, err)
	}
	b.StopTimer()
}

func BenchmarkRunLocksGC(b *testing.B) {
	testutils.IntegrationTest(b)
	kvstore.SetupDummyWithConfigOpts(b, "etcd", etcdOpts)
	benchmarkRunLocksGC(b, "etcd")
}

func benchmarkRunLocksGC(b *testing.B, backendName string) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + b.N)
	// FIXME: Did this previously use allocatorName := randomTestName() ? so TestAllocatorKey(randomeTestName())
	backend1, err := NewKVStoreBackend(KVStoreBackendConfiguration{allocatorName, "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(b, err)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend1, allocator.WithMax(maxID), allocator.WithoutGC())
	require.NoError(b, err)
	shortKey := TestAllocatorKey("1;")

	staleLocks := map[string]kvstore.Value{}
	staleLocks, err = allocator.RunLocksGC(context.Background(), staleLocks)
	require.NoError(b, err)
	require.Empty(b, staleLocks)

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
		require.NoError(b, err)
		close(gotLock1)
		client, _ := kvstore.NewClient(context.Background(),
			backendName,
			map[string]string{
				kvstore.EtcdAddrOption: kvstore.EtcdDummyAddress(),
			},
			nil,
		)
		lock2, err = client.LockPath(context.Background(), allocatorName+"/locks/"+kvstore.Client().Encode([]byte(shortKey.GetKey())))
		require.NoError(b, err)
		close(gotLock2)
	}()

	// Wait until lock1 is gotten.
	select {
	case <-gotLock1:
	case <-time.After(timeout):
		b.Error("Lock1 not obtained on time")
	}

	// wait until client2, in line 160, tries to grab the lock.
	// We can't detect when that actually happen so we have to assume it will
	// happen within one second.
	time.Sleep(time.Second)

	// Check which locks are stale, it should be lock1 and lock2
	staleLocks, err = allocator.RunLocksGC(context.Background(), staleLocks)
	require.NoError(b, err)
	require.Len(b, staleLocks, 2)

	var (
		oldestRev     = uint64(math.MaxUint64)
		oldestLeaseID int64
		oldestKey     string
	)
	// Stale locks contains 2 locks, which is expected but we only want to GC
	// the oldest one so we can unlock all the remaining clients waiting to hold
	// the lock.
	for k, v := range staleLocks {
		if v.ModRevision < oldestRev {
			oldestKey = k
			oldestRev = v.ModRevision
			oldestLeaseID = v.LeaseID
		}
	}

	// store the oldest key in the map so that it can be GCed.
	staleLocks = map[string]kvstore.Value{}
	staleLocks[oldestKey] = kvstore.Value{
		ModRevision: oldestRev,
		LeaseID:     oldestLeaseID,
	}

	// GC lock1 because it's the oldest lock being held.
	staleLocks, err = allocator.RunLocksGC(context.Background(), staleLocks)
	require.NoError(b, err)
	// There are 2 clients trying to get the lock, we have GC one of them
	// so that is way we have 1 staleLock in the map.
	require.Len(b, staleLocks, 1)

	// Wait until lock2 is gotten as it should have happen since we have
	// GC lock1.
	select {
	case <-gotLock2:
	case <-time.After(timeout):
		b.Error("Lock2 not obtained on time")
	}

	// Unlock lock1 because we still hold the local locks.
	err = lock1.Unlock(context.Background())
	require.NoError(b, err)
	err = lock2.Unlock(context.Background())
	require.NoError(b, err)
}

func BenchmarkGC(b *testing.B) {
	testutils.IntegrationTest(b)
	kvstore.SetupDummyWithConfigOpts(b, "etcd", etcdOpts)
	benchmarkGC(b)
}

func benchmarkGC(b *testing.B) {
	allocatorName := randomTestName()
	maxID := idpool.ID(256 + b.N)
	// FIXME: Did this previously use allocatorName := randomTestName() ? so TestAllocatorKey(randomeTestName())
	backend, err := NewKVStoreBackend(KVStoreBackendConfiguration{allocatorName, "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(b, err)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID), allocator.WithoutGC())
	require.NoError(b, err)
	require.NotNil(b, allocator)
	defer allocator.DeleteAllKeys()
	defer allocator.Delete()

	allocator.DeleteAllKeys()

	shortKey := TestAllocatorKey("1;")
	shortID, _, _, err := allocator.Allocate(context.Background(), shortKey)
	require.NoError(b, err)
	require.NotEqual(b, 0, shortID)

	longKey := TestAllocatorKey("1;2;")
	longID, _, _, err := allocator.Allocate(context.Background(), longKey)
	require.NoError(b, err)
	require.NotEqual(b, 0, longID)

	_, err = allocator.Release(context.Background(), shortKey)
	require.NoError(b, err)

	rateLimiter := rate.NewLimiter(10*time.Second, 100)

	keysToDelete := map[string]uint64{}
	keysToDelete, _, err = allocator.RunGC(rateLimiter, keysToDelete)
	require.NoError(b, err)
	require.Len(b, keysToDelete, 1)
	keysToDelete, _, err = allocator.RunGC(rateLimiter, keysToDelete)
	require.NoError(b, err)
	require.Len(b, keysToDelete, 0)

	// wait for cache to be updated via delete notification
	require.EventuallyWithT(b, func(c *assert.CollectT) {
		key, err := allocator.GetByID(context.TODO(), shortID)
		assert.NoError(c, err)
		assert.Nil(c, key)
	}, timeout, tick)

	key, err := allocator.GetByID(context.TODO(), shortID)
	require.NoError(b, err)
	require.Nil(b, key)
}

func BenchmarkGCShouldSkipOutOfRangeIdentities(b *testing.B) {
	testutils.IntegrationTest(b)
	kvstore.SetupDummyWithConfigOpts(b, "etcd", etcdOpts)
	benchmarkGCShouldSkipOutOfRangeIdentities(b)
}

func benchmarkGCShouldSkipOutOfRangeIdentities(b *testing.B) {
	// Allocator1: allocator under test
	backend, err := NewKVStoreBackend(KVStoreBackendConfiguration{randomTestName(), "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(b, err)

	maxID1 := idpool.ID(4 + b.N)
	allocator1, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID1), allocator.WithoutGC())
	require.NoError(b, err)
	require.NotNil(b, allocator1)

	defer allocator1.DeleteAllKeys()
	defer allocator1.Delete()

	allocator1.DeleteAllKeys()

	shortKey1 := TestAllocatorKey("1;")
	shortID1, _, _, err := allocator1.Allocate(context.Background(), shortKey1)
	require.NoError(b, err)
	require.NotEqual(b, 0, shortID1)

	_, err = allocator1.Release(context.Background(), shortKey1)
	require.NoError(b, err)

	// Alloctor2: with a non-overlapping range compared with allocator1
	backend2, err := NewKVStoreBackend(KVStoreBackendConfiguration{randomTestName(), "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(b, err)

	minID2 := maxID1 + 1
	maxID2 := minID2 + 4
	allocator2, err := allocator.NewAllocator(TestAllocatorKey(""), backend2, allocator.WithMin(minID2), allocator.WithMax(maxID2), allocator.WithoutGC())
	require.NoError(b, err)
	require.NotNil(b, allocator2)

	shortKey2 := TestAllocatorKey("2;")
	shortID2, _, _, err := allocator2.Allocate(context.Background(), shortKey2)
	require.NoError(b, err)
	require.NotEqual(b, 0, shortID2)

	defer allocator2.DeleteAllKeys()
	defer allocator2.Delete()

	allocator2.Release(context.Background(), shortKey2)

	// Perform GC with allocator1: there are two entries in kvstore currently
	rateLimiter := rate.NewLimiter(10*time.Second, 100)

	keysToDelete := map[string]uint64{}
	keysToDelete, _, err = allocator1.RunGC(rateLimiter, keysToDelete)
	require.NoError(b, err)
	// But, only one will be filtered out and GC'ed
	require.Len(b, keysToDelete, 1)
	keysToDelete, _, err = allocator1.RunGC(rateLimiter, keysToDelete)
	require.NoError(b, err)
	require.Len(b, keysToDelete, 0)

	// Wait for cache to be updated via delete notification
	require.EventuallyWithT(b, func(c *assert.CollectT) {
		key, err := allocator1.GetByID(context.TODO(), shortID1)
		assert.NoError(c, err)
		assert.Nil(c, key)
	}, timeout, tick)

	// The key created with allocator1 should be GC'd
	key, err := allocator1.GetByID(context.TODO(), shortID1)
	require.NoError(b, err)
	require.Nil(b, key)

	// The key created with allocator2 should NOT be GC'd
	key2, err := allocator2.GetByID(context.TODO(), shortID2)
	require.NoError(b, err)
	require.NotNil(b, key2)
}

func TestAllocateCached(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testAllocatorCached(t, idpool.ID(32), randomTestName()) // enable use of local cache
}

func testAllocatorCached(t *testing.T, maxID idpool.ID, allocatorName string) {
	backend, err := NewKVStoreBackend(KVStoreBackendConfiguration{allocatorName, "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(t, err)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend,
		allocator.WithMax(maxID), allocator.WithoutGC())
	require.NoError(t, err)
	require.NotNil(t, a)

	// remove any keys which might be leftover
	a.DeleteAllKeys()

	// allocate all available IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, newLocally, err := a.Allocate(context.Background(), key)
		require.NoError(t, err)
		require.NotEqual(t, 0, id)
		require.True(t, new)
		require.True(t, newLocally)
	}

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, newLocally, err := a.Allocate(context.Background(), key)
		require.NoError(t, err)
		require.NotEqual(t, 0, id)
		require.False(t, new)
		require.False(t, newLocally)
	}

	// Create a 2nd allocator, refill it
	backend2, err := NewKVStoreBackend(KVStoreBackendConfiguration{allocatorName, "r", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(t, err)
	a2, err := allocator.NewAllocator(TestAllocatorKey(""), backend2,
		allocator.WithMax(maxID), allocator.WithoutGC())
	require.NoError(t, err)
	require.NotNil(t, a2)

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, newLocally, err := a2.Allocate(context.Background(), key)
		require.NoError(t, err)
		require.NotEqual(t, 0, id)
		require.False(t, new)
		require.True(t, newLocally)

		a2.Release(context.Background(), key)
	}

	// release 2nd reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		_, err := a.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
		require.NoError(t, err)
	}

	staleKeysPreviousRound := map[string]uint64{}
	rateLimiter := rate.NewLimiter(10*time.Second, 100)
	// running the GC should not evict any entries
	staleKeysPreviousRound, _, err = a.RunGC(rateLimiter, staleKeysPreviousRound)
	require.NoError(t, err)

	v, err := kvstore.Client().ListPrefix(context.TODO(), path.Join(allocatorName, "id"))
	require.NoError(t, err)
	require.Len(t, v, int(maxID))

	// release final reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		_, err := a.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
		require.NoError(t, err)
	}

	// running the GC should evict all entries
	staleKeysPreviousRound, _, err = a.RunGC(rateLimiter, staleKeysPreviousRound)
	require.NoError(t, err)
	_, _, err = a.RunGC(rateLimiter, staleKeysPreviousRound)
	require.NoError(t, err)

	v, err = kvstore.Client().ListPrefix(context.TODO(), path.Join(allocatorName, "id"))
	require.NoError(t, err)
	require.Len(t, v, 0)

	a.DeleteAllKeys()
	a.Delete()
	a2.Delete()
}

func TestKeyToID(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testKeyToID(t)
}

func testKeyToID(t *testing.T) {
	allocatorName := randomTestName()
	backend, err := NewKVStoreBackend(KVStoreBackendConfiguration{allocatorName, "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(t, err)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend)
	require.NoError(t, err)
	require.NotNil(t, a)

	// An error is returned because the path is outside the prefix (allocatorName/id)
	id, err := backend.(*kvstoreBackend).keyToID(path.Join(allocatorName, "invalid"))
	require.NotNil(t, err)
	require.Equal(t, idpool.NoID, id)

	// An error is returned because the path contains the prefix
	// (allocatorName/id) but cannot be parsed ("invalid")
	id, err = backend.(*kvstoreBackend).keyToID(path.Join(allocatorName, "id", "invalid"))
	require.NotNil(t, err)
	require.Equal(t, idpool.NoID, id)

	// A valid lookup that finds an ID
	id, err = backend.(*kvstoreBackend).keyToID(path.Join(allocatorName, "id", "10"))
	require.NoError(t, err)
	require.Equal(t, idpool.ID(10), id)
}

func TestGetNoCache(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testGetNoCache(t, idpool.ID(256))
}

func testGetNoCache(t *testing.T, maxID idpool.ID) {
	allocatorName := randomTestName()
	backend, err := NewKVStoreBackend(KVStoreBackendConfiguration{allocatorName, "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(t, err)
	allocator, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(maxID), allocator.WithoutGC())
	require.NoError(t, err)
	require.NotNil(t, allocator)

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()
	defer allocator.DeleteAllKeys()

	labelsLong := "foo;/;bar;"
	key := TestAllocatorKey(fmt.Sprintf("%s%010d", labelsLong, 0))
	longID, new, newLocally, err := allocator.Allocate(context.Background(), key)
	require.NoError(t, err)
	require.NotEqual(t, 0, longID)
	require.True(t, new)
	require.True(t, newLocally)

	observedID, err := allocator.GetNoCache(context.Background(), key)
	require.NoError(t, err)
	require.NotEqual(t, 0, observedID)

	labelsShort := "foo;/;"
	shortKey := TestAllocatorKey(labelsShort)
	observedID, err = allocator.GetNoCache(context.Background(), shortKey)
	require.NoError(t, err)
	require.Equal(t, idpool.NoID, observedID)

	shortID, new, newLocally, err := allocator.Allocate(context.Background(), shortKey)
	require.NoError(t, err)
	require.NotEqual(t, 0, shortID)
	require.True(t, new)
	require.True(t, newLocally)

	observedID, err = allocator.GetNoCache(context.Background(), shortKey)
	require.NoError(t, err)
	require.Equal(t, shortID, observedID)
}

func TestPrefixMatchesKey(t *testing.T) {
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
		t.Logf("prefixMatchesKey(%q, %q) expected to be %t", tt.prefix, tt.key, tt.expected)
		result := prefixMatchesKey(tt.prefix, tt.key)
		require.Equal(t, tt.expected, result)
	}
}

func TestRemoteCache(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testRemoteCache(t)
}

func testRemoteCache(t *testing.T) {
	testName := randomTestName()
	backend, err := NewKVStoreBackend(KVStoreBackendConfiguration{testName, "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(t, err)
	a, err := allocator.NewAllocator(TestAllocatorKey(""), backend, allocator.WithMax(idpool.ID(256)))
	require.NoError(t, err)
	require.NotNil(t, a)

	// remove any keys which might be leftover
	a.DeleteAllKeys()

	defer func() {
		a.DeleteAllKeys()
		a.Delete()
	}()

	// allocate all available IDs
	for i := idpool.ID(1); i <= idpool.ID(4); i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		_, _, _, err := a.Allocate(context.Background(), key)
		require.NoError(t, err)
	}

	// wait for main cache to be populated
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cacheLen := 0
		a.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
			cacheLen++
		})
		assert.EqualValues(c, 4, cacheLen)
	}, timeout, tick)

	// count identical allocations returned
	cache := map[idpool.ID]int{}
	a.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
		cache[id]++
	})

	// ForeachCache must have returned 4 allocations all unique
	require.Len(t, cache, 4)
	for i := range cache {
		require.Equal(t, 1, cache[i])
	}

	// watch the prefix in the same kvstore via a 2nd watcher
	backend2, err := NewKVStoreBackend(KVStoreBackendConfiguration{testName, "a", TestAllocatorKey(""), kvstore.Client()})
	require.NoError(t, err)
	a2, err := allocator.NewAllocator(TestAllocatorKey(""), backend2, allocator.WithMax(idpool.ID(256)),
		allocator.WithoutAutostart(), allocator.WithoutGC())
	require.NoError(t, err)

	rc := a.NewRemoteCache("remote", a2)
	require.NotNil(t, rc)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()
		wg.Wait()
	}()

	wg.Add(1)
	go func() {
		rc.Watch(ctx, func(ctx context.Context) {})
		wg.Done()
	}()

	// wait for remote cache to be populated
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cacheLen := 0
		a.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
			cacheLen++
		})
		// 4 local + 4 remote
		assert.EqualValues(c, 8, cacheLen)
	}, timeout, tick)

	// count the allocations in the main cache *AND* the remote cache
	cache = map[idpool.ID]int{}
	a.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
		cache[id]++
	})

	// Foreach must have returned 4 allocations each duplicated, once in
	// the main cache, once in the remote cache
	require.Len(t, cache, 4)
	for i := range cache {
		require.Equal(t, 2, cache[i])
	}
}
