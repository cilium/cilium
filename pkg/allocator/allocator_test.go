// Copyright 2016-2017 Authors of Cilium
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
	"testing"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/lock"
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

func (d *dummyBackend) DeleteAllKeys() {
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

func (d *dummyBackend) AcquireReference(ctx context.Context, id idpool.ID, key AllocatorKey) error {
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

func (d *dummyLock) Unlock() error {
	return nil
}

func (d *dummyBackend) Lock(ctx context.Context, key AllocatorKey) (Lock, error) {
	return &dummyLock{}, nil
}

func (d *dummyBackend) UpdateKey(id idpool.ID, key AllocatorKey, reliablyMissing bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.identities[id] = key
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

func (d *dummyBackend) GetByID(id idpool.ID) (AllocatorKey, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	if key, ok := d.identities[id]; ok {
		return key, nil
	}
	return nil, nil
}

func (d *dummyBackend) Release(ctx context.Context, key AllocatorKey) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	for id, k := range d.identities {
		if k.GetKey() == key.GetKey() {
			delete(d.identities, id)
			if d.handler != nil {
				d.handler.OnDelete(id, k)
			}
			return nil
		}
	}
	return fmt.Errorf("identity does not exist")
}

func (d *dummyBackend) ListAndWatch(handler CacheMutations, stopChan chan struct{}) {
	d.mutex.Lock()
	d.handler = handler
	for id, k := range d.identities {
		d.handler.OnModify(id, k)
	}
	d.mutex.Unlock()
	d.handler.OnListDone()
	<-stopChan
}

func (d *dummyBackend) RunGC() error {
	return nil
}

func (d *dummyBackend) Status() (string, error) {
	return "", nil
}

type TestType string

func (t TestType) GetKey() string              { return string(t) }
func (t TestType) GetAsMap() map[string]string { return map[string]string{string(t): string(t)} }
func (t TestType) String() string              { return string(t) }
func (t TestType) PutKey(v string) (AllocatorKey, error) {
	return TestType(v), nil
}
func (t TestType) PutKeyFromMap(m map[string]string) AllocatorKey {
	for _, v := range m {
		return TestType(v)
	}

	panic("empty map")
}

func randomTestName() string {
	return testutils.RandomRuneWithPrefix(testPrefix, 12)
}

func (s *AllocatorSuite) TestSelectID(c *C) {
	minID, maxID := idpool.ID(1), idpool.ID(5)
	backend := newDummyBackend()
	a, err := NewAllocator(TestType(""), backend, WithMin(minID), WithMax(maxID))
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
	minID, maxID := idpool.ID(1), idpool.ID(5)
	backend := newDummyBackend()
	a, err := NewAllocator(TestType(""), backend, WithMin(minID), WithMax(maxID), WithPrefixMask(1<<16))
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
	allocator, err := NewAllocator(TestType(""), backend, WithMax(maxID), WithoutGC())
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
	allocator2, err := NewAllocator(TestType(""), backend, WithMax(maxID), WithoutGC())
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

	// running the GC should not evict any entries
	allocator.RunGC()

	// release final reference of all IDs
	for i := idpool.ID(1); i <= maxID; i++ {
		allocator.Release(context.Background(), TestType(fmt.Sprintf("key%04d", i)))
	}

	for i := idpool.ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		c.Assert(allocator.localKeys.keys[key.GetKey()], IsNil)
	}

	// running the GC should evict all entries
	allocator.RunGC()

	allocator.DeleteAllKeys()
	allocator.Delete()
	allocator2.Delete()
}

func (s *AllocatorSuite) TestAllocateCached(c *C) {
	testAllocator(c, idpool.ID(256), randomTestName(), "a") // enable use of local cache
}
