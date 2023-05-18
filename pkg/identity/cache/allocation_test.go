// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	cacheKey "github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	fakeConfig "github.com/cilium/cilium/pkg/option/fake"
	"github.com/cilium/cilium/pkg/testutils"
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

	mgr := NewCachingIdentityAllocator(newDummyOwner())
	<-mgr.InitIdentityAllocator(nil)

	c.Assert(identity.IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityHost)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameWorld: labels.NewLabel(labels.IDNameWorld, "", labels.LabelSourceReserved),
	}
	c.Assert(identity.IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityWorld)
	c.Assert(isNew, Equals, false)

	c.Assert(identity.IdentityAllocationIsLocal(labels.LabelHealth), Equals, true)
	i, isNew, err = mgr.AllocateIdentity(context.Background(), labels.LabelHealth, false, identity.InvalidIdentity)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityHealth)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	c.Assert(identity.IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityInit)
	c.Assert(isNew, Equals, false)

	lbls = labels.Labels{
		labels.IDNameUnmanaged: labels.NewLabel(labels.IDNameUnmanaged, "", labels.LabelSourceReserved),
	}
	c.Assert(identity.IdentityAllocationIsLocal(lbls), Equals, true)
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	c.Assert(err, IsNil)
	c.Assert(i.ID, Equals, identity.ReservedIdentityUnmanaged)
	c.Assert(isNew, Equals, false)
}

type IdentityAllocatorSuite struct{}

func (ias *IdentityAllocatorSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

type IdentityAllocatorEtcdSuite struct {
	IdentityAllocatorSuite
}

var _ = Suite(&IdentityAllocatorEtcdSuite{})

func (e *IdentityAllocatorEtcdSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

func (e *IdentityAllocatorEtcdSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")
}

func (e *IdentityAllocatorEtcdSuite) TearDownTest(c *C) {
	kvstore.Client().Close(context.TODO())
}

type IdentityAllocatorConsulSuite struct {
	IdentityAllocatorSuite
}

var _ = Suite(&IdentityAllocatorConsulSuite{})

func (e *IdentityAllocatorConsulSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

func (e *IdentityAllocatorConsulSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("consul")
}

func (e *IdentityAllocatorConsulSuite) TearDownTest(c *C) {
	kvstore.Client().Close(context.TODO())
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

// WaitUntilID waits until an update event is received for the
// 'target' identity and returns the number of events processed to get
// there. Returns 0 in case of 'd.updated' channel is closed or
// nothing is received from that channel in 60 seconds.
func (d *dummyOwner) WaitUntilID(target identity.NumericIdentity) int {
	rounds := 0
	timer, timerDone := inctimer.New()
	defer timerDone()
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
		case <-timer.After(60 * time.Second):
			// Timed out waiting for KV-store events
			return 0
		}
	}
}

func (ias *IdentityAllocatorSuite) TestEventWatcherBatching(c *C) {
	owner := newDummyOwner()
	events := make(allocator.AllocatorEventChan, 1024)
	watcher := identityWatcher{
		owner: owner,
	}

	watcher.watch(events)

	lbls := labels.NewLabelsFromSortedList("id=foo")
	key := &cacheKey.GlobalIdentity{LabelArray: lbls.LabelArray()}

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
	identity.InitWellKnownIdentities(&fakeConfig.Config{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(newDummyOwner())
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()
	defer mgr.IdentityAllocator.DeleteAllKeys()

	cache := mgr.GetIdentityCache()
	_, ok := cache[identity.ReservedCiliumKVStore]
	c.Assert(ok, Equals, true)
}

func (ias *IdentityAllocatorSuite) TestAllocator(c *C) {
	lbls1 := labels.NewLabelsFromSortedList("blah=%%//!!;id=foo;user=anna")
	lbls2 := labels.NewLabelsFromSortedList("id=bar;user=anna")
	lbls3 := labels.NewLabelsFromSortedList("id=bar;user=susan")

	owner := newDummyOwner()
	identity.InitWellKnownIdentities(&fakeConfig.Config{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(owner)
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()
	defer mgr.IdentityAllocator.DeleteAllKeys()

	id1a, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	c.Assert(id1a, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	// Wait for the update event from the KV-store
	c.Assert(owner.WaitUntilID(id1a.ID), Not(Equals), 0)
	c.Assert(owner.GetIdentity(id1a.ID), checker.DeepEquals, lbls1.LabelArray())

	// reuse the same identity
	id1b, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	c.Assert(id1b, Not(IsNil))
	c.Assert(isNew, Equals, false)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Equals, id1b.ID)

	released, err := mgr.Release(context.Background(), id1a, false)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, false)
	released, err = mgr.Release(context.Background(), id1b, false)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
	// KV-store still keeps the ID even when a single node has released it.
	// This also means that we should have not received an event from the
	// KV-store for the deletion of the identity, so it should still be in
	// owner's cache.
	c.Assert(owner.GetIdentity(id1a.ID), checker.DeepEquals, lbls1.LabelArray())

	id1b, isNew, err = mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	c.Assert(id1b, Not(IsNil))
	c.Assert(err, IsNil)
	// the value key should not have been removed so the same ID should be
	// assigned again and it should not be marked as new
	c.Assert(isNew, Equals, false)
	c.Assert(id1a.ID, Equals, id1b.ID)
	// Should still be cached, no new events should have been received.
	c.Assert(owner.GetIdentity(id1a.ID), checker.DeepEquals, lbls1.LabelArray())

	ident := mgr.LookupIdentityByID(context.TODO(), id1b.ID)
	c.Assert(ident, Not(IsNil))
	c.Assert(lbls1, checker.DeepEquals, ident.Labels)

	id2, isNew, err := mgr.AllocateIdentity(context.Background(), lbls2, false, identity.InvalidIdentity)
	c.Assert(id2, Not(IsNil))
	c.Assert(isNew, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Not(Equals), id2.ID)
	// Wait for the update event from the KV-store
	c.Assert(owner.WaitUntilID(id2.ID), Not(Equals), 0)
	c.Assert(owner.GetIdentity(id2.ID), checker.DeepEquals, lbls2.LabelArray())

	id3, isNew, err := mgr.AllocateIdentity(context.Background(), lbls3, false, identity.InvalidIdentity)
	c.Assert(id3, Not(IsNil))
	c.Assert(isNew, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(id1a.ID, Not(Equals), id3.ID)
	c.Assert(id2.ID, Not(Equals), id3.ID)
	// Wait for the update event from the KV-store
	c.Assert(owner.WaitUntilID(id3.ID), Not(Equals), 0)
	c.Assert(owner.GetIdentity(id3.ID), checker.DeepEquals, lbls3.LabelArray())

	released, err = mgr.Release(context.Background(), id1b, false)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
	released, err = mgr.Release(context.Background(), id2, false)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)
	released, err = mgr.Release(context.Background(), id3, false)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)

	mgr.IdentityAllocator.DeleteAllKeys()
	c.Assert(owner.WaitUntilID(id3.ID), Not(Equals), 0)
}

func (ias *IdentityAllocatorSuite) TestLocalAllocation(c *C) {
	lbls1 := labels.NewLabelsFromSortedList("cidr:192.0.2.3/32")

	owner := newDummyOwner()
	identity.InitWellKnownIdentities(&fakeConfig.Config{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(owner)
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()
	defer mgr.IdentityAllocator.DeleteAllKeys()

	id, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	c.Assert(id.ID.HasLocalScope(), Equals, true)
	// Wait for the update event from the KV-store
	c.Assert(owner.WaitUntilID(id.ID), Not(Equals), 0)
	c.Assert(owner.GetIdentity(id.ID), checker.DeepEquals, lbls1.LabelArray())

	// reuse the same identity
	id, isNew, err = mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	cache := mgr.GetIdentityCache()
	c.Assert(cache[id.ID], Not(IsNil))

	// 1st Release, not released
	released, err := mgr.Release(context.Background(), id, false)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, false)

	// Identity still exists
	c.Assert(owner.GetIdentity(id.ID), checker.DeepEquals, lbls1.LabelArray())

	// 2nd Release, released
	released, err = mgr.Release(context.Background(), id, false)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)

	// Wait until the identity is released
	c.Assert(owner.WaitUntilID(id.ID), Not(Equals), 0)
	// Identity does not exist any more
	c.Assert(owner.GetIdentity(id.ID), IsNil)

	cache = mgr.GetIdentityCache()
	c.Assert(cache[id.ID], IsNil)

	id, isNew, err = mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	c.Assert(id, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	c.Assert(id.ID.HasLocalScope(), Equals, true)

	released, err = mgr.Release(context.Background(), id, false)
	c.Assert(err, IsNil)
	c.Assert(released, Equals, true)

	mgr.IdentityAllocator.DeleteAllKeys()
	c.Assert(owner.WaitUntilID(id.ID), Not(Equals), 0)
}

// Test that we can close and reopen the allocator successfully.
func (s *IdentityCacheTestSuite) TestAllocatorReset(c *C) {
	labels := labels.NewLabelsFromSortedList("id=bar;user=anna")
	owner := newDummyOwner()
	mgr := NewCachingIdentityAllocator(owner)
	testAlloc := func() {
		id1a, _, err := mgr.AllocateIdentity(context.Background(), labels, false, identity.InvalidIdentity)
		c.Assert(id1a, Not(IsNil))
		c.Assert(err, IsNil)

		queued, ok := <-owner.updated
		c.Assert(ok, Equals, true)
		c.Assert(queued, Equals, id1a.ID)
	}

	<-mgr.InitIdentityAllocator(nil)
	testAlloc()
	mgr.Close()
	<-mgr.InitIdentityAllocator(nil)
	testAlloc()
	mgr.Close()
}
