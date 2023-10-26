// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/stream"
)

const (
	testPrefix = "test-prefix"
)

func Test(t *testing.T) {
	TestingT(t)
}

type AllocatorSuite struct{}

var _ = Suite(&AllocatorSuite{})

type dummyBackend struct {
	mutex      lock.RWMutex
	identities map[idpool.ID]AllocatorKey
	handler    CacheMutations

	disableListDone bool
}

func newDummyBackend() Backend {
	return &dummyBackend{
		identities: map[idpool.ID]AllocatorKey{},
	}
}

func (d *dummyBackend) Encode(v string) string {
	return v
}

func (d *dummyBackend) DeleteAllKeys(ctx context.Context) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.identities = map[idpool.ID]AllocatorKey{}
}

func (d *dummyBackend) AllocateID(ctx context.Context, id idpool.ID, key AllocatorKey) (AllocatorKey, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, ok := d.identities[id]; ok {
		return nil, fmt.Errorf("identity already exists")
	}

	d.identities[id] = key

	if d.handler != nil {
		d.handler.OnAdd(id, key)
	}

	return key, nil
}

func (d *dummyBackend) AllocateIDIfLocked(ctx context.Context, id idpool.ID, key AllocatorKey, lock kvstore.KVLocker) (AllocatorKey, error) {
	return d.AllocateID(ctx, id, key)
}

func (d *dummyBackend) AcquireReference(ctx context.Context, id idpool.ID, key AllocatorKey, lock kvstore.KVLocker) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, ok := d.identities[id]; !ok {
		return fmt.Errorf("identity does not exist")
	}

	if d.handler != nil {
		d.handler.OnModify(id, key)
	}

	return nil
}

type dummyLock struct{}

func (d *dummyLock) Unlock(ctx context.Context) error {
	return nil
}

func (d *dummyLock) Comparator() interface{} {
	return nil
}

func (d *dummyBackend) Lock(ctx context.Context, key AllocatorKey) (kvstore.KVLocker, error) {
	return &dummyLock{}, nil
}

func (d *dummyBackend) UpdateKey(ctx context.Context, id idpool.ID, key AllocatorKey, reliablyMissing bool) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.identities[id] = key
	return nil
}

func (d *dummyBackend) UpdateKeyIfLocked(ctx context.Context, id idpool.ID, key AllocatorKey, reliablyMissing bool, lock kvstore.KVLocker) error {
	return d.UpdateKey(ctx, id, key, reliablyMissing)
}

func (d *dummyBackend) Get(ctx context.Context, key AllocatorKey) (idpool.ID, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	for id, k := range d.identities {
		if key.GetKey() == k.GetKey() {
			return id, nil
		}
	}
	return idpool.NoID, nil
}

func (d *dummyBackend) GetIfLocked(ctx context.Context, key AllocatorKey, lock kvstore.KVLocker) (idpool.ID, error) {
	return d.Get(ctx, key)
}

func (d *dummyBackend) GetByID(ctx context.Context, id idpool.ID) (AllocatorKey, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	if key, ok := d.identities[id]; ok {
		return key, nil
	}
	return nil, nil
}

func (d *dummyBackend) Release(ctx context.Context, id idpool.ID, key AllocatorKey) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	for idtyID, k := range d.identities {
		if k.GetKey() == key.GetKey() &&
			idtyID == id {
			delete(d.identities, id)
			if d.handler != nil {
				d.handler.OnDelete(id, k)
			}
			return nil
		}
	}
	return fmt.Errorf("identity does not exist")
}

func (d *dummyBackend) ListAndWatch(ctx context.Context, handler CacheMutations, stopChan chan struct{}) {
	d.mutex.Lock()
	d.handler = handler

	// Sort by ID to ensure consistent ordering
	ids := maps.Keys(d.identities)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		d.handler.OnModify(id, d.identities[id])
	}
	d.mutex.Unlock()

	if !d.disableListDone {
		d.handler.OnListDone()
	}

	<-stopChan
}

func (d *dummyBackend) RunLocksGC(_ context.Context, _ map[string]kvstore.Value) (map[string]kvstore.Value, error) {
	return nil, nil
}

func (d *dummyBackend) RunGC(context.Context, *rate.Limiter, map[string]uint64, idpool.ID, idpool.ID) (map[string]uint64, *GCStats, error) {
	return nil, nil, nil
}

func (d *dummyBackend) Status() (string, error) {
	return "", nil
}

type TestAllocatorKey string

func (t TestAllocatorKey) GetKey() string { return string(t) }
func (t TestAllocatorKey) GetAsMap() map[string]string {
	return map[string]string{string(t): string(t)}
}
func (t TestAllocatorKey) String() string { return string(t) }
func (t TestAllocatorKey) PutKey(v string) AllocatorKey {
	return TestAllocatorKey(v)
}
func (t TestAllocatorKey) PutKeyFromMap(m map[string]string) AllocatorKey {
	for _, v := range m {
		return TestAllocatorKey(v)
	}

	panic("empty map")
}

func (t TestAllocatorKey) PutValue(key any, value any) AllocatorKey {
	panic("not implemented")
}

func (t TestAllocatorKey) Value(any) any {
	panic("not implemented")
}

func randomTestName() string {
	return rand.RandomStringWithPrefix(testPrefix, 12)
}

func (s *AllocatorSuite) TestSelectID(c *C) {
	minID, maxID := idpool.ID(1), idpool.ID(5)
	backend := newDummyBackend()
	a, err := NewAllocator(TestAllocatorKey(""), backend, WithMin(minID), WithMax(maxID))
	c.Assert(err, IsNil)
	c.Assert(a, Not(IsNil))

	// allocate all available IDs
	for i := minID; i <= maxID; i++ {
		id, val, unmaskedID := a.selectAvailableID()
		c.Assert(id, Not(Equals), idpool.NoID)
		c.Assert(val, Equals, id.String())
		c.Assert(id, Equals, unmaskedID)
		a.mainCache.mutex.Lock()
		a.mainCache.cache[id] = TestAllocatorKey(fmt.Sprintf("key-%d", i))
		a.mainCache.mutex.Unlock()
	}

	// we should be out of IDs
	id, val, unmaskedID := a.selectAvailableID()
	c.Assert(id, Equals, idpool.ID(0))
	c.Assert(id, Equals, unmaskedID)
	c.Assert(val, Equals, "")
}

func (s *AllocatorSuite) TestPrefixMask(c *C) {
	minID, maxID := idpool.ID(1), idpool.ID(5)
	backend := newDummyBackend()
	a, err := NewAllocator(TestAllocatorKey(""), backend, WithMin(minID), WithMax(maxID), WithPrefixMask(1<<16))
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

func testAllocator(c *C, maxID idpool.ID, allocatorName string, suffix string) {
	backend := newDummyBackend()
	allocator, err := NewAllocator(TestAllocatorKey(""), backend, WithMax(maxID), WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()

	// allocate all available IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, firstUse, err := allocator.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, true)
		c.Assert(firstUse, Equals, true)

		// refcnt must be 1
		c.Assert(allocator.localKeys.keys[allocator.encodeKey(key)].refcnt, Equals, uint64(1))
	}

	saved := allocator.backoffTemplate.Factor
	allocator.backoffTemplate.Factor = 1.0

	// we should be out of id space here
	_, new, firstUse, err := allocator.Allocate(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", maxID+1)))
	c.Assert(err, Not(IsNil))
	c.Assert(new, Equals, false)
	c.Assert(firstUse, Equals, false)

	allocator.backoffTemplate.Factor = saved

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, firstUse, err := allocator.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)
		c.Assert(firstUse, Equals, false)

		// refcnt must now be 2
		c.Assert(allocator.localKeys.keys[allocator.encodeKey(key)].refcnt, Equals, uint64(2))
	}

	// Create a 2nd allocator, refill it
	allocator2, err := NewAllocator(TestAllocatorKey(""), backend, WithMax(maxID), WithoutGC())
	c.Assert(err, IsNil)
	c.Assert(allocator2, Not(IsNil))

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, firstUse, err := allocator2.Allocate(context.Background(), key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)
		c.Assert(firstUse, Equals, true)

		localKey := allocator2.localKeys.keys[allocator.encodeKey(key)]
		c.Assert(localKey, Not(IsNil))

		// refcnt in the 2nd allocator is 1
		c.Assert(localKey.refcnt, Equals, uint64(1))

		allocator2.Release(context.Background(), key)
	}

	// release 2nd reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		allocator.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
	}

	// refcnt should be back to 1
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		c.Assert(allocator.localKeys.keys[allocator.encodeKey(key)].refcnt, Equals, uint64(1))
	}

	rateLimiter := rate.NewLimiter(10*time.Second, 100)

	// running the GC should not evict any entries
	allocator.RunGC(rateLimiter, nil)

	// release final reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		allocator.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
	}

	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		c.Assert(allocator.localKeys.keys[allocator.encodeKey(key)], IsNil)
	}

	// running the GC should evict all entries
	allocator.RunGC(rateLimiter, nil)

	allocator.DeleteAllKeys()
	allocator.Delete()
	allocator2.Delete()
}

func (s *AllocatorSuite) TestAllocateCached(c *C) {
	testAllocator(c, idpool.ID(256), randomTestName(), "a") // enable use of local cache
}

func TestObserveAllocatorChanges(t *testing.T) {
	backend := newDummyBackend()
	allocator, err := NewAllocator(TestAllocatorKey(""), backend, WithMin(idpool.ID(1)), WithMax(idpool.ID(256)), WithoutGC())
	require.NoError(t, err)
	require.NotNil(t, allocator)

	numAllocations := 10

	// Allocate few ids
	for i := 0; i < numAllocations; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, firstUse, err := allocator.Allocate(context.Background(), key)
		require.NoError(t, err)
		require.NotEqual(t, 0, id)
		require.True(t, new)
		require.True(t, firstUse)

		// refcnt must be 1
		require.Equal(t, uint64(1), allocator.localKeys.keys[allocator.encodeKey(key)].refcnt)
	}

	// Subscribe to the changes. This should replay the current state.
	ctx, cancel := context.WithCancel(context.Background())
	changes := stream.ToChannel[AllocatorChange](ctx, allocator)
	for i := 0; i < numAllocations; i++ {
		change := <-changes
		// Since these are replayed in hash map traversal order, just validate that
		// the fields are set.
		require.True(t, strings.HasPrefix(change.Key.String(), "key0"))
		require.NotEqual(t, 0, change.ID)
		require.Equal(t, AllocatorChangeUpsert, change.Kind)
	}

	// After replay we should see a sync event.
	change := <-changes
	require.Equal(t, AllocatorChangeSync, change.Kind)

	// Simulate changes to the allocations via the backend
	go func() {
		backend.(*dummyBackend).handler.OnAdd(idpool.ID(123), TestAllocatorKey("remote"))
		backend.(*dummyBackend).handler.OnDelete(idpool.ID(123), TestAllocatorKey("remote"))
	}()

	// Check that we observe the allocation and the deletions.
	change = <-changes
	require.Equal(t, AllocatorChangeUpsert, change.Kind)
	require.Equal(t, TestAllocatorKey("remote"), change.Key)

	change = <-changes
	require.Equal(t, AllocatorChangeDelete, change.Kind)
	require.Equal(t, TestAllocatorKey("remote"), change.Key)

	// Cancel the subscription and verify it completes.
	cancel()
	_, notClosed := <-changes
	require.False(t, notClosed)
}

// The following tests are currently disabled as they are not 100% reliable in
// the Jenkins CI.
// These were copied from pkg/kvstore/allocator/allocator_test.go and don't
// compile anymore. They assume that dummyBackend can be shared between many
// allocators in order to test parallel allocations.
//
//func testParallelAllocator(c *C, maxID idpool.ID, allocatorName string, suffix string) {
//	allocator, err := NewAllocator(allocatorName, TestAllocatorKey(""), WithMax(maxID), WithSuffix(suffix))
//	c.Assert(err, IsNil)
//	c.Assert(allocator, Not(IsNil))
//
//	// allocate all available IDs
//	for i := idpool.ID(1); i <= maxID; i++ {
//		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
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
//	_, new, err := allocator.Allocate(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", maxID+1)))
//	c.Assert(err, Not(IsNil))
//	c.Assert(new, Equals, false)
//
//	allocator.backoffTemplate.Factor = saved
//
//	// allocate all IDs again using the same set of keys, refcnt should go to 2
//	for i := idpool.ID(1); i <= maxID; i++ {
//		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
//		id, _, err := allocator.Allocate(context.Background(), key)
//		c.Assert(err, IsNil)
//		c.Assert(id, Not(Equals), 0)
//
//		// refcnt must now be 2
//		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(2))
//	}
//
//	for i := idpool.ID(1); i <= maxID; i++ {
//		allocator.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
//	}
//
//	// release final reference of all IDs
//	for i := idpool.ID(1); i <= maxID; i++ {
//		allocator.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
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
//	a, err := NewAllocator(allocatorName, TestAllocatorKey(""), WithSuffix("a"))
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

func TestWatchRemoteKVStore(t *testing.T) {
	var wg sync.WaitGroup
	var synced bool

	run := func(ctx context.Context, rc *RemoteCache) context.CancelFunc {
		ctx, cancel := context.WithCancel(ctx)
		wg.Add(1)
		go func() {
			rc.Watch(ctx, func(context.Context) { synced = true })
			wg.Done()
		}()
		return cancel
	}

	stop := func(cancel context.CancelFunc) {
		cancel()
		wg.Wait()
		synced = false
	}

	global := Allocator{remoteCaches: make(map[string]*RemoteCache)}
	events := make(AllocatorEventChan, 10)

	ctx, cancel := context.WithCancel(context.Background())

	// Ensure that the goroutines are properly collected also in case the test fails.
	defer stop(cancel)

	newRemoteAllocator := func(backend Backend) *Allocator {
		remote, err := NewAllocator(TestAllocatorKey(""), backend, WithEvents(events), WithoutAutostart(), WithoutGC())
		require.NoError(t, err)

		return remote
	}

	// Add a new remote cache, and assert that it is registered correctly
	// and the proper events are emitted
	backend := newDummyBackend()
	remote := newRemoteAllocator(backend)

	backend.AllocateID(ctx, idpool.ID(1), TestAllocatorKey("foo"))
	backend.AllocateID(ctx, idpool.ID(2), TestAllocatorKey("baz"))

	rc := global.NewRemoteCache("remote", remote)
	require.False(t, rc.Synced(), "The cache should not be synchronized")
	cancel = run(ctx, rc)

	require.Equal(t, AllocatorEvent{ID: idpool.ID(1), Key: TestAllocatorKey("foo"), Typ: kvstore.EventTypeModify}, <-events)
	require.Equal(t, AllocatorEvent{ID: idpool.ID(2), Key: TestAllocatorKey("baz"), Typ: kvstore.EventTypeModify}, <-events)

	require.Eventually(t, func() bool {
		global.remoteCachesMutex.RLock()
		defer global.remoteCachesMutex.RUnlock()
		return global.remoteCaches["remote"] == rc
	}, 1*time.Second, 10*time.Millisecond)

	require.True(t, rc.Synced(), "The cache should now be synchronized")
	require.True(t, synced, "The on-sync callback should have been executed")
	stop(cancel)
	require.False(t, rc.Synced(), "The cache should no longer be synchronized when stopped")

	// Add a new remote cache with the same name, and assert that it overrides
	// the previous one, and the proper events are emitted (including deletions
	// for all stale keys)
	backend = newDummyBackend()
	remote = newRemoteAllocator(backend)

	backend.AllocateID(ctx, idpool.ID(1), TestAllocatorKey("qux"))
	backend.AllocateID(ctx, idpool.ID(5), TestAllocatorKey("bar"))

	rc = global.NewRemoteCache("remote", remote)
	cancel = run(ctx, rc)

	require.Equal(t, AllocatorEvent{ID: idpool.ID(1), Key: TestAllocatorKey("qux"), Typ: kvstore.EventTypeModify}, <-events)
	require.Equal(t, AllocatorEvent{ID: idpool.ID(5), Key: TestAllocatorKey("bar"), Typ: kvstore.EventTypeModify}, <-events)
	require.Equal(t, AllocatorEvent{ID: idpool.ID(2), Key: TestAllocatorKey("baz"), Typ: kvstore.EventTypeDelete}, <-events)

	require.Eventually(t, func() bool {
		global.remoteCachesMutex.RLock()
		defer global.remoteCachesMutex.RUnlock()
		return global.remoteCaches["remote"] == rc
	}, 1*time.Second, 10*time.Millisecond)

	stop(cancel)

	// Add a new remote cache with the same name, but cancel the context before
	// the ListDone event is received, and assert that it does not override the
	// existing entry. A deletion event should also be emitted for any object
	// detected as part of the initial list operation, which was not present in
	// the existing cache.
	backend = newDummyBackend()
	backend.(*dummyBackend).disableListDone = true
	remote = newRemoteAllocator(backend)
	backend.AllocateID(ctx, idpool.ID(1), TestAllocatorKey("qux"))
	backend.AllocateID(ctx, idpool.ID(7), TestAllocatorKey("foo"))

	oc := global.NewRemoteCache("remote", remote)
	cancel = run(ctx, oc)

	require.Equal(t, AllocatorEvent{ID: idpool.ID(1), Key: TestAllocatorKey("qux"), Typ: kvstore.EventTypeModify}, <-events)
	require.Equal(t, AllocatorEvent{ID: idpool.ID(7), Key: TestAllocatorKey("foo"), Typ: kvstore.EventTypeModify}, <-events)
	require.False(t, rc.Synced(), "The cache should not be synchronized if the ListDone event has not been received")
	require.False(t, synced, "The on-sync callback should not have been executed if the ListDone event has not been received")

	stop(cancel)

	require.Equal(t, AllocatorEvent{ID: idpool.ID(7), Key: TestAllocatorKey("foo"), Typ: kvstore.EventTypeDelete}, <-events)
	require.Equal(t, rc, global.remoteCaches["remote"])

	require.Len(t, events, 0)

	// Remove the remote caches and assert that a deletion event is triggered
	// for all entries.
	global.RemoveRemoteKVStore("remote")

	require.Len(t, events, 2)

	// Given that the drained events are spilled out from a map there is no
	// ordering guarantee; hence, let's sort them before checking.
	drained := make([]AllocatorEvent, 2)
	drained[0] = <-events
	drained[1] = <-events
	sort.Slice(drained, func(i, j int) bool { return drained[i].ID < drained[j].ID })

	require.Equal(t, AllocatorEvent{ID: idpool.ID(1), Key: TestAllocatorKey("qux"), Typ: kvstore.EventTypeDelete}, drained[0])
	require.Equal(t, AllocatorEvent{ID: idpool.ID(5), Key: TestAllocatorKey("bar"), Typ: kvstore.EventTypeDelete}, drained[1])
}
