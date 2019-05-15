// Copyright 2016-2018 Authors of Cilium
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

package cache

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"

	. "gopkg.in/check.v1"
)

func (s *IdentityCacheTestSuite) TestAllocateIdentityReserved(c *C) {
	var (
		lbls  labels.Labels
		i     *identity.Identity
		isNew bool
		err   error
	)

	lbls = labels.Labels{
		labels.IDNameHost: labels.NewLabel(labels.IDNameHost, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), nil, lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityHost)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameWorld: labels.NewLabel(labels.IDNameWorld, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), nil, lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityWorld)
	c.Assert(isNew, Equals, false)

	c.Assert(IdentityAllocationIsLocal(labels.LabelHealth), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), nil, labels.LabelHealth)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityHealth)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), nil, lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityInit)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameUnmanaged: labels.NewLabel(labels.IDNameUnmanaged, "", labels.LabelSourceReserved),
	}
	c.Assert(IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = AllocateIdentity(context.Background(), nil, lbls)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityUnmanaged)
	c.Assert(isNew, Equals, false)
}

type IdentityAllocatorSuite struct{}

type IdentityAllocatorEtcdSuite struct {
	IdentityAllocatorSuite
}

var _ = Suite(&IdentityAllocatorEtcdSuite{})

func (e *IdentityAllocatorEtcdSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")
}

type IdentityAllocatorConsulSuite struct {
	IdentityAllocatorSuite
}

var _ = Suite(&IdentityAllocatorConsulSuite{})

func (e *IdentityAllocatorConsulSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("consul")
}

type dummyOwner struct {
	updated chan identity.NumericIdentity
	mutex   lock.Mutex
	cache   IdentityCache
}

func newDummyOwner() *dummyOwner {
	return &dummyOwner{
		cache:   IdentityCache{},
		updated: make(chan identity.NumericIdentity, 1024),
	}
}

func (d *dummyOwner) UpdateIdentities(added, deleted IdentityCache) {
	d.mutex.Lock()
	log.Debugf("Dummy UpdateIdentities(added: %v, deleted: %v)", added, deleted)
	for id, lbls := range added {
		d.cache[id] = lbls
		d.updated <- id
	}
	for id := range deleted {
		delete(d.cache, id)
		d.updated <- id
	}
	d.mutex.Unlock()
}

func (d *dummyOwner) GetIdentity(id identity.NumericIdentity) labels.LabelArray {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.cache[id]
}

func (d *dummyOwner) GetNodeSuffix() string {
	return "foo"
}

// WaitUntilCount waits until the cached identity count reaches
// 'target' and returns the number of events processed to get
// there. Returns 0 in case of 'd.updated' channel is closed or
// nothing is received from that channel in 60 seconds.
func (d *dummyOwner) WaitUntilID(target identity.NumericIdentity) int {
	rounds := 0
	for {
		select {
		case nid, ok := <-d.updated:
			if !ok {
				// updates channel closed
				return 0
			}
			rounds++
			if nid == target {
				return rounds
			}
		case <-time.After(60 * time.Second):
			// Timed out waiting for KV-store events
			return 0
		}
	}
}

func (ias *IdentityAllocatorSuite) TestEventWatcherBatching(c *C) {
	owner := newDummyOwner()
	events := make(allocator.AllocatorEventChan, 1024)
	var watcher identityWatcher

	watcher.watch(owner, events)
	defer close(watcher.stopChan)

	lbls := labels.NewLabelsFromSortedList("id=foo")
	key := globalIdentity{lbls.LabelArray()}

	for i := 1024; i < 1034; i++ {
		events <- allocator.AllocatorEvent{
			Typ: kvstore.EventTypeCreate,
			ID:  idpool.ID(i),
			Key: key,
		}
	}
	c.Assert(owner.WaitUntilID(1033), Not(Equals), 0)
	c.Assert(owner.GetIdentity(identity.NumericIdentity(1033)), checker.DeepEquals, lbls.LabelArray())
	for i := 1024; i < 1034; i++ {
		events <- allocator.AllocatorEvent{
			Typ: kvstore.EventTypeDelete,
			ID:  idpool.ID(i),
		}
	}
	c.Assert(owner.WaitUntilID(1033), Not(Equals), 0)
	for i := 2048; i < 2058; i++ {
		events <- allocator.AllocatorEvent{
			Typ: kvstore.EventTypeCreate,
			ID:  idpool.ID(i),
			Key: key,
		}
	}
	for i := 2048; i < 2053; i++ {
		events <- allocator.AllocatorEvent{
			Typ: kvstore.EventTypeDelete,
			ID:  idpool.ID(i),
		}
	}
	c.Assert(owner.WaitUntilID(2052), Not(Equals), 0)
	c.Assert(owner.GetIdentity(identity.NumericIdentity(2052)), IsNil) // Pooling removed the add

	for i := 2053; i < 2058; i++ {
		events <- allocator.AllocatorEvent{
			Typ: kvstore.EventTypeDelete,
			ID:  idpool.ID(i),
		}
	}
	c.Assert(owner.WaitUntilID(2057), Not(Equals), 0)
}

func (ias *IdentityAllocatorSuite) TestGetIdentityCache(c *C) {
	identity.InitWellKnownIdentities()
	InitIdentityAllocator(newDummyOwner())
	defer Close()
	defer IdentityAllocator.DeleteAllKeys()

	cache := GetIdentityCache()
	_, ok := cache[identity.ReservedCiliumKVStore]
	c.Assert(ok, Equals, true)
}

func (ias *IdentityAllocatorSuite) TestAllocator(c *C) {
	lbls1 := labels.NewLabelsFromSortedList("blah=%%//!!;id=foo;user=anna")
	lbls2 := labels.NewLabelsFromSortedList("id=bar;user=anna")
	lbls3 := labels.NewLabelsFromSortedList("id=bar;user=susan")

	owner := newDummyOwner()
	identity.InitWellKnownIdentities()
	InitIdentityAllocator(owner)
	defer Close()
	defer IdentityAllocator.DeleteAllKeys()

	id1a, isNew, err := AllocateIdentity(context.Background(), nil, lbls1)
	c.Assert(id1a, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	// Wait for the update event from the KV-store
	c.Assert(owner.WaitUntilID(id1a.ID), Not(Equals), 0)
	c.Assert(owner.GetIdentity(id1a.ID), checker.DeepEquals, lbls1.LabelArray())

	// reuse the same identity
	id1b, isNew, err := AllocateIdentity(context.Background(), nil, lbls1)
	c.Assert(id1b, Not(IsNil))
	c.Assert(isNew, Equals, false)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Equals, id1b.ID)

	released, err := Release(context.Background(), nil, id1a)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, false)
	released, err = Release(context.Background(), nil, id1b)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
	// KV-store still keeps the ID even when a single node has released it.
	// This also means that we should have not received an event from the
	// KV-store for the deletion of the identity, so it should still be in
	// owner's cache.
	c.Assert(owner.GetIdentity(id1a.ID), checker.DeepEquals, lbls1.LabelArray())

	id1b, isNew, err = AllocateIdentity(context.Background(), nil, lbls1)
	c.Assert(id1b, Not(IsNil))
	c.Assert(err, IsNil)
	// the value key should not have been removed so the same ID should be
	// assigned again and it should not be marked as new
	c.Assert(isNew, Equals, false)
	c.Assert(id1a.ID, Equals, id1b.ID)
	// Should still be cached, no new events should have been received.
	c.Assert(owner.GetIdentity(id1a.ID), checker.DeepEquals, lbls1.LabelArray())

	identity := LookupIdentityByID(id1b.ID)
	c.Assert(identity, Not(IsNil))
	c.Assert(lbls1, checker.DeepEquals, identity.Labels)

	id2, isNew, err := AllocateIdentity(context.Background(), nil, lbls2)
	c.Assert(id2, Not(IsNil))
	c.Assert(isNew, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Not(Equals), id2.ID)
	// Wait for the update event from the KV-store
	c.Assert(owner.WaitUntilID(id2.ID), Not(Equals), 0)
	c.Assert(owner.GetIdentity(id2.ID), checker.DeepEquals, lbls2.LabelArray())

	id3, isNew, err := AllocateIdentity(context.Background(), nil, lbls3)
	c.Assert(id3, Not(IsNil))
	c.Assert(isNew, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Not(Equals), id3.ID)
	c.Assert(id2.ID, Not(Equals), id3.ID)
	// Wait for the update event from the KV-store
	c.Assert(owner.WaitUntilID(id3.ID), Not(Equals), 0)
	c.Assert(owner.GetIdentity(id3.ID), checker.DeepEquals, lbls3.LabelArray())

	released, err = Release(context.Background(), nil, id1b)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
	released, err = Release(context.Background(), nil, id2)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
	released, err = Release(context.Background(), nil, id3)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)

	IdentityAllocator.DeleteAllKeys()
	c.Assert(owner.WaitUntilID(id3.ID), Not(Equals), 0)
}

func (ias *IdentityAllocatorSuite) TestLocalAllocationr(c *C) {
	lbls1 := labels.NewLabelsFromSortedList("cidr:192.0.2.3/32")

	owner := newDummyOwner()
	identity.InitWellKnownIdentities()
	InitIdentityAllocator(owner)
	defer Close()
	defer IdentityAllocator.DeleteAllKeys()

	id, isNew, err := AllocateIdentity(context.Background(), nil, lbls1)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	c.Assert(id.ID.HasLocalScope(), Equals, true)
	// Wait for the update event from the KV-store
	c.Assert(owner.WaitUntilID(id.ID), Not(Equals), 0)
	c.Assert(owner.GetIdentity(id.ID), checker.DeepEquals, lbls1.LabelArray())

	// reuse the same identity
	id, isNew, err = AllocateIdentity(context.Background(), nil, lbls1)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	cache := GetIdentityCache()
	c.Assert(cache[id.ID], Not(IsNil))

	released, err := Release(context.Background(), nil, id)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, false)
	released, err = Release(context.Background(), nil, id)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)

	// KV-store still holds on to the key, so it is not deleted yet via KV-store events
	// This may be racy, as timing here depends on scheduling.
	c.Assert(owner.GetIdentity(id.ID), checker.DeepEquals, lbls1.LabelArray())

	cache = GetIdentityCache()
	c.Assert(cache[id.ID], IsNil)

	id, isNew, err = AllocateIdentity(context.Background(), nil, lbls1)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	c.Assert(id.ID.HasLocalScope(), Equals, true)

	released, err = Release(context.Background(), nil, id)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)

	IdentityAllocator.DeleteAllKeys()
	c.Assert(owner.WaitUntilID(id.ID), Not(Equals), 0)
}
