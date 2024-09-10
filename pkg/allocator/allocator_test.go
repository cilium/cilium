// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/rate"
)

type dummyBackend struct {
	mutex      lock.RWMutex
	identities map[idpool.ID]AllocatorKey
	handler    CacheMutations

	updateKey func(ctx context.Context, id idpool.ID, key AllocatorKey) error

	disableListDone bool
}

func newDummyBackend() *dummyBackend {
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

func (d *dummyBackend) DeleteID(ctx context.Context, id idpool.ID) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	delete(d.identities, id)
	return nil
}

func (d *dummyBackend) AllocateID(ctx context.Context, id idpool.ID, key AllocatorKey) (AllocatorKey, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, ok := d.identities[id]; ok {
		return nil, fmt.Errorf("identity already exists")
	}

	d.identities[id] = key

	if d.handler != nil {
		d.handler.OnUpsert(id, key)
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
		d.handler.OnUpsert(id, key)
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

func (d *dummyBackend) setUpdateKeyMutator(mutator func(ctx context.Context, id idpool.ID, key AllocatorKey) error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.updateKey = mutator
}

func (d *dummyBackend) UpdateKey(ctx context.Context, id idpool.ID, key AllocatorKey, reliablyMissing bool) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.identities[id] = key
	if d.updateKey != nil {
		return d.updateKey(ctx, id, key)
	}
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

func (d *dummyBackend) ListIDs(ctx context.Context) (identityIDs []idpool.ID, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return slices.Collect(maps.Keys(d.identities)), nil
}

func (d *dummyBackend) ListAndWatch(ctx context.Context, handler CacheMutations, stopChan chan struct{}) {
	d.mutex.Lock()
	d.handler = handler

	// Sort by ID to ensure consistent ordering
	for _, id := range slices.Sorted(maps.Keys(d.identities)) {
		d.handler.OnUpsert(id, d.identities[id])
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

func TestSelectID(t *testing.T) {
	minID, maxID := idpool.ID(1), idpool.ID(5)
	backend := newDummyBackend()
	a, err := NewAllocator(TestAllocatorKey(""), backend, WithMin(minID), WithMax(maxID))
	require.NoError(t, err)
	require.NotNil(t, a)

	// allocate all available IDs
	for i := minID; i <= maxID; i++ {
		id, val, unmaskedID := a.selectAvailableID()
		require.NotEqual(t, idpool.NoID, id)
		require.Equal(t, id.String(), val)
		require.Equal(t, unmaskedID, id)
		a.mainCache.mutex.Lock()
		a.mainCache.cache[id] = TestAllocatorKey(fmt.Sprintf("key-%d", i))
		a.mainCache.mutex.Unlock()
	}

	// we should be out of IDs
	id, val, unmaskedID := a.selectAvailableID()
	require.Equal(t, idpool.ID(0), id)
	require.Equal(t, unmaskedID, id)
	require.Equal(t, "", val)
}

func TestPrefixMask(t *testing.T) {
	minID, maxID := idpool.ID(1), idpool.ID(5)
	backend := newDummyBackend()
	a, err := NewAllocator(TestAllocatorKey(""), backend, WithMin(minID), WithMax(maxID), WithPrefixMask(1<<16))
	require.NoError(t, err)
	require.NotNil(t, a)

	// allocate all available IDs
	for i := minID; i <= maxID; i++ {
		id, val, unmaskedID := a.selectAvailableID()
		require.NotEqual(t, idpool.NoID, id)
		require.Equal(t, idpool.ID(1), id>>16)
		require.NotEqual(t, unmaskedID, id)
		require.Equal(t, id.String(), val)
	}

	a.Delete()
}

func testAllocator(t *testing.T, maxID idpool.ID) {
	backend := newDummyBackend()
	allocator, err := NewAllocator(TestAllocatorKey(""), backend, WithMax(maxID), WithoutGC())
	require.NoError(t, err)
	require.NotNil(t, allocator)

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()

	// allocate all available IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, firstUse, err := allocator.Allocate(context.Background(), key)
		require.NoError(t, err)
		require.NotEqual(t, 0, id)
		require.True(t, new)
		require.True(t, firstUse)

		// refcnt must be 1
		require.Equal(t, uint64(1), allocator.localKeys.keys[allocator.encodeKey(key)].refcnt)
	}

	saved := allocator.backoffTemplate.Factor
	allocator.backoffTemplate.Factor = 1.0

	// we should be out of id space here
	_, new, firstUse, err := allocator.Allocate(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", maxID+1)))
	require.Error(t, err)
	require.False(t, new)
	require.False(t, firstUse)

	allocator.backoffTemplate.Factor = saved

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, firstUse, err := allocator.Allocate(context.Background(), key)
		require.NoError(t, err)
		require.NotEqual(t, 0, id)
		require.False(t, new)
		require.False(t, firstUse)

		// refcnt must now be 2
		require.Equal(t, uint64(2), allocator.localKeys.keys[allocator.encodeKey(key)].refcnt)
	}

	// Create a 2nd allocator, refill it
	allocator2, err := NewAllocator(TestAllocatorKey(""), backend, WithMax(maxID), WithoutGC())
	require.NoError(t, err)
	require.NotNil(t, allocator2)

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		id, new, firstUse, err := allocator2.Allocate(context.Background(), key)
		require.NoError(t, err)
		require.NotEqual(t, 0, id)
		require.False(t, new)
		require.True(t, firstUse)

		localKey := allocator2.localKeys.keys[allocator.encodeKey(key)]
		require.NotNil(t, localKey)

		// refcnt in the 2nd allocator is 1
		require.Equal(t, uint64(1), localKey.refcnt)

		allocator2.Release(context.Background(), key)
	}

	// release 2nd reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		allocator.Release(context.Background(), TestAllocatorKey(fmt.Sprintf("key%04d", i)))
	}

	// refcnt should be back to 1
	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestAllocatorKey(fmt.Sprintf("key%04d", i))
		require.Equal(t, uint64(1), allocator.localKeys.keys[allocator.encodeKey(key)].refcnt)
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
		require.NotContains(t, allocator.localKeys.keys, allocator.encodeKey(key))
	}

	// running the GC should evict all entries
	allocator.RunGC(rateLimiter, nil)

	allocator.DeleteAllKeys()
	allocator.Delete()
	allocator2.Delete()
}

func TestAllocateCached(t *testing.T) {
	testAllocator(t, idpool.ID(256)) // enable use of local cache
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
		backend.handler.OnUpsert(idpool.ID(123), TestAllocatorKey("remote"))
		backend.handler.OnDelete(idpool.ID(123), TestAllocatorKey("remote"))
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

// TestHandleK8sDelete tests the behavior of the allocator of handling OnDelete events
// when master key protection is enabled vs disabled.
func TestHandleK8sDelete(t *testing.T) {

	masterKeyRecreateMaxInterval = time.Millisecond
	backend := newDummyBackend()

	alloc, err := NewAllocator(TestAllocatorKey(""), backend)
	alloc.idPool = idpool.NewIDPool(1234, 1234)
	alloc.enableMasterKeyProtection = true
	require.NoError(t, err)

	_, newlyAllocated, first, err := alloc.Allocate(context.Background(), TestAllocatorKey("foo"))
	require.NoError(t, err)
	require.True(t, first)
	require.True(t, newlyAllocated)

	var counter atomic.Uint32
	backend.setUpdateKeyMutator(func(ctx context.Context, id idpool.ID, key AllocatorKey) error {
		counter.Add(1)
		if counter.Load() <= 2 {
			return fmt.Errorf("updateKey failed: %d", counter.Load())
		}
		return nil
	})

	assertBackendContains := func(t assert.TestingT, id int, key string) {
		k, err := backend.GetByID(context.TODO(), idpool.ID(id))
		assert.NoError(t, err)
		assert.Equal(t, key, k.GetKey())
	}

	// 1. Simulate a delete event, where master key protection is enabled
	// and the identity is owned locally.
	assertBackendContains(t, 1234, "foo")

	alloc.mainCache.OnDelete(1234, TestAllocatorKey("foo"))
	// Check that the identity was retried multiple times by master key protection.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, uint32(3), counter.Load())
	}, time.Second, time.Millisecond)

	assert.Contains(t, alloc.mainCache.nextCache, idpool.ID(1234))
	assert.Contains(t, alloc.mainCache.nextKeyCache, "foo")

	// 2. Simulate a delete event, where master key protection is disabled.
	alloc.enableMasterKeyProtection = false
	alloc.mainCache.OnDelete(1234, TestAllocatorKey("foo"))
	assert.NotContains(t, alloc.mainCache.nextCache, idpool.ID(1234))
	assert.NotContains(t, alloc.mainCache.nextKeyCache, "foo")

	// 3. Simulate delete event where master key protection is enabled
	// but the identity is not owned locally.
	alloc.enableMasterKeyProtection = true
	alloc.mainCache.OnUpsert(4321, TestAllocatorKey("bar"))
	assert.Contains(t, alloc.mainCache.nextCache, idpool.ID(4321))
	assert.Contains(t, alloc.mainCache.nextKeyCache, "bar")
	alloc.mainCache.OnDelete(idpool.ID(4321), TestAllocatorKey("bar"))
	assert.NotContains(t, alloc.mainCache.nextCache, idpool.ID(4321))
	assert.NotContains(t, alloc.mainCache.nextKeyCache, "bar")
}

func TestWatchRemoteKVStore(t *testing.T) {
	var wg sync.WaitGroup
	var synced atomic.Bool

	run := func(ctx context.Context, rc *RemoteCache) context.CancelFunc {
		ctx, cancel := context.WithCancel(ctx)
		wg.Add(1)
		go func() {
			rc.Watch(ctx, func(context.Context) { synced.Store(true) })
			wg.Done()
		}()
		return cancel
	}

	stop := func(cancel context.CancelFunc) {
		cancel()
		wg.Wait()
		synced.Store(false)
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

	require.Equal(t, AllocatorEvent{ID: idpool.ID(1), Key: TestAllocatorKey("foo"), Typ: AllocatorChangeUpsert}, <-events)
	require.Equal(t, AllocatorEvent{ID: idpool.ID(2), Key: TestAllocatorKey("baz"), Typ: AllocatorChangeUpsert}, <-events)

	require.Eventually(t, func() bool {
		global.remoteCachesMutex.RLock()
		defer global.remoteCachesMutex.RUnlock()
		return global.remoteCaches["remote"] == rc
	}, 1*time.Second, 10*time.Millisecond)

	require.True(t, rc.Synced(), "The cache should now be synchronized")
	require.True(t, synced.Load(), "The on-sync callback should have been executed")
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

	require.Equal(t, AllocatorEvent{ID: idpool.ID(1), Key: TestAllocatorKey("qux"), Typ: AllocatorChangeUpsert}, <-events)
	require.Equal(t, AllocatorEvent{ID: idpool.ID(5), Key: TestAllocatorKey("bar"), Typ: AllocatorChangeUpsert}, <-events)
	require.Equal(t, AllocatorEvent{ID: idpool.ID(2), Key: TestAllocatorKey("baz"), Typ: AllocatorChangeDelete}, <-events)

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
	backend.disableListDone = true
	remote = newRemoteAllocator(backend)
	backend.AllocateID(ctx, idpool.ID(1), TestAllocatorKey("qux"))
	backend.AllocateID(ctx, idpool.ID(7), TestAllocatorKey("foo"))

	oc := global.NewRemoteCache("remote", remote)
	cancel = run(ctx, oc)

	require.Equal(t, AllocatorEvent{ID: idpool.ID(1), Key: TestAllocatorKey("qux"), Typ: AllocatorChangeUpsert}, <-events)
	require.Equal(t, AllocatorEvent{ID: idpool.ID(7), Key: TestAllocatorKey("foo"), Typ: AllocatorChangeUpsert}, <-events)
	require.False(t, rc.Synced(), "The cache should not be synchronized if the ListDone event has not been received")
	require.False(t, synced.Load(), "The on-sync callback should not have been executed if the ListDone event has not been received")

	stop(cancel)

	require.Equal(t, AllocatorEvent{ID: idpool.ID(7), Key: TestAllocatorKey("foo"), Typ: AllocatorChangeDelete}, <-events)
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

	require.Equal(t, AllocatorEvent{ID: idpool.ID(1), Key: TestAllocatorKey("qux"), Typ: AllocatorChangeDelete}, drained[0])
	require.Equal(t, AllocatorEvent{ID: idpool.ID(5), Key: TestAllocatorKey("bar"), Typ: AllocatorChangeDelete}, drained[1])
}

func TestCacheValidators(t *testing.T) {
	const (
		validID   = 10
		invalidID = 11
		key       = TestAllocatorKey("key")
	)

	var (
		kind    AllocatorChangeKind
		backend = &dummyBackend{disableListDone: true}
		events  = make(chan AllocatorEvent, 1)
	)

	allocator, err := NewAllocator(
		TestAllocatorKey(""), backend,
		WithEvents(events), WithoutGC(),
		WithCacheValidator(func(k AllocatorChangeKind, id idpool.ID, _ AllocatorKey) error {
			kind = k
			if id == invalidID {
				return errors.New("invalid")
			}
			return nil
		}),
	)
	require.NoError(t, err)
	allocator.mainCache.OnListDone()

	t.Cleanup(func() { allocator.Delete() })

	allocator.mainCache.OnUpsert(validID, key)
	require.Len(t, events, 1, "Valid upsert event should be propagated")
	require.Equal(t, AllocatorEvent{AllocatorChangeUpsert, validID, key}, <-events)
	require.Equal(t, key, allocator.mainCache.getByID(validID))
	require.Equal(t, AllocatorChangeUpsert, kind)

	allocator.mainCache.OnDelete(validID, key)
	require.Len(t, events, 1, "Valid deletion event should be propagated")
	require.Equal(t, AllocatorEvent{AllocatorChangeDelete, validID, key}, <-events)
	require.Nil(t, allocator.mainCache.getByID(validID))
	require.Equal(t, AllocatorChangeDelete, kind)

	allocator.mainCache.OnUpsert(invalidID, key)
	require.Empty(t, events, "Invalid upsert event should not be propagated")
	require.Nil(t, allocator.mainCache.getByID(invalidID))
	require.Equal(t, AllocatorChangeUpsert, kind)

	allocator.mainCache.OnDelete(invalidID, key)
	require.Empty(t, events, "Invalid delete event should not be propagated")
	require.Nil(t, allocator.mainCache.getByID(invalidID))
	require.Equal(t, AllocatorChangeDelete, kind)
}
