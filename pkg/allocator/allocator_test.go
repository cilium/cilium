// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/rate"
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

func (d *dummyBackend) AllocateID(ctx context.Context, id idpool.ID, key AllocatorKey) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, ok := d.identities[id]; ok {
		return fmt.Errorf("identity already exists")
	}

	d.identities[id] = key

	if d.handler != nil {
		d.handler.OnAdd(id, key)
	}

	return nil
}

func (d *dummyBackend) AllocateIDIfLocked(ctx context.Context, id idpool.ID, key AllocatorKey, lock kvstore.KVLocker) error {
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
	for id, k := range d.identities {
		d.handler.OnModify(id, k)
	}
	d.mutex.Unlock()
	d.handler.OnListDone()
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
