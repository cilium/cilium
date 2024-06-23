// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/allocator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	cacheKey "github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var fakeConfig = &option.DaemonConfig{
	K8sNamespace: "kube-system",
}

func TestAllocateIdentityReserved(t *testing.T) {
	for _, be := range []string{"etcd", "consul"} {
		t.Run(be, func(t *testing.T) {
			testutils.IntegrationTest(t)
			kvstore.SetupDummy(t, be)
			testAllocateIdentityReserved(t)
		})
	}
}

func testAllocateIdentityReserved(t *testing.T) {
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

	require.Equal(t, true, identity.IdentityAllocationIsLocal(lbls))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityHost, i.ID)
	require.False(t, isNew)

	lbls = labels.Labels{
		labels.IDNameWorld: labels.NewLabel(labels.IDNameWorld, "", labels.LabelSourceReserved),
	}
	require.Equal(t, true, identity.IdentityAllocationIsLocal(lbls))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityWorld, i.ID)
	require.False(t, isNew)

	require.Equal(t, true, identity.IdentityAllocationIsLocal(labels.LabelHealth))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), labels.LabelHealth, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityHealth, i.ID)
	require.False(t, isNew)

	lbls = labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	require.Equal(t, true, identity.IdentityAllocationIsLocal(lbls))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityInit, i.ID)
	require.False(t, isNew)

	lbls = labels.Labels{
		labels.IDNameUnmanaged: labels.NewLabel(labels.IDNameUnmanaged, "", labels.LabelSourceReserved),
	}
	require.Equal(t, true, identity.IdentityAllocationIsLocal(lbls))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityUnmanaged, i.ID)
	require.False(t, isNew)
}

type dummyOwner struct {
	updated chan identity.NumericIdentity
	mutex   lock.Mutex
	cache   identity.IdentityMap
}

func newDummyOwner() *dummyOwner {
	return &dummyOwner{
		cache:   identity.IdentityMap{},
		updated: make(chan identity.NumericIdentity, 1024),
	}
}

func (d *dummyOwner) UpdateIdentities(added, deleted identity.IdentityMap) {
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

func TestEventWatcherBatching(t *testing.T) {
	for _, be := range []string{"etcd", "consul"} {
		t.Run(be, func(t *testing.T) {
			testutils.IntegrationTest(t)
			kvstore.SetupDummy(t, be)
			testEventWatcherBatching(t)
		})
	}
}

func testEventWatcherBatching(t *testing.T) {
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
			Typ: allocator.AllocatorChangeUpsert,
			ID:  idpool.ID(i),
			Key: key,
		}
	}
	require.NotEqual(t, 0, owner.WaitUntilID(1033))
	require.EqualValues(t, lbls.LabelArray(), owner.GetIdentity(identity.NumericIdentity(1033)))
	for i := 1024; i < 1034; i++ {
		events <- allocator.AllocatorEvent{
			Typ: allocator.AllocatorChangeDelete,
			ID:  idpool.ID(i),
		}
	}
	require.NotEqual(t, 0, owner.WaitUntilID(1033))
	for i := 2048; i < 2058; i++ {
		events <- allocator.AllocatorEvent{
			Typ: allocator.AllocatorChangeUpsert,
			ID:  idpool.ID(i),
			Key: key,
		}
	}
	for i := 2048; i < 2053; i++ {
		events <- allocator.AllocatorEvent{
			Typ: allocator.AllocatorChangeDelete,
			ID:  idpool.ID(i),
		}
	}
	require.NotEqual(t, 0, owner.WaitUntilID(2052))
	require.Nil(t, owner.GetIdentity(identity.NumericIdentity(2052))) // Pooling removed the add

	for i := 2053; i < 2058; i++ {
		events <- allocator.AllocatorEvent{
			Typ: allocator.AllocatorChangeDelete,
			ID:  idpool.ID(i),
		}
	}
	require.NotEqual(t, 0, owner.WaitUntilID(2057))
}

func TestGetIdentityCache(t *testing.T) {
	for _, be := range []string{"etcd", "consul"} {
		t.Run(be, func(t *testing.T) {
			testutils.IntegrationTest(t)
			kvstore.SetupDummy(t, be)
			testGetIdentityCache(t)
		})
	}
}

func testGetIdentityCache(t *testing.T) {
	identity.InitWellKnownIdentities(fakeConfig, cmtypes.ClusterInfo{Name: "default", ID: 5})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(newDummyOwner())
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()
	defer mgr.IdentityAllocator.DeleteAllKeys()

	cache := mgr.GetIdentityCache()
	_, ok := cache[identity.ReservedCiliumKVStore]
	require.Equal(t, true, ok)
}

func TestAllocator(t *testing.T) {
	for _, be := range []string{"etcd", "consul"} {
		t.Run(be, func(t *testing.T) {
			testutils.IntegrationTest(t)
			kvstore.SetupDummy(t, be)
			testAllocator(t)
		})
	}
}

func testAllocator(t *testing.T) {
	lbls1 := labels.NewLabelsFromSortedList("blah=%%//!!;id=foo;user=anna")
	lbls2 := labels.NewLabelsFromSortedList("id=bar;user=anna")
	lbls3 := labels.NewLabelsFromSortedList("id=bar;user=susan")

	owner := newDummyOwner()
	identity.InitWellKnownIdentities(fakeConfig, cmtypes.ClusterInfo{Name: "default", ID: 5})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(owner)
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()
	defer mgr.IdentityAllocator.DeleteAllKeys()

	id1a, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	require.NotNil(t, id1a)
	require.NoError(t, err)
	require.Equal(t, true, isNew)
	// Wait for the update event from the KV-store
	require.NotEqual(t, 0, owner.WaitUntilID(id1a.ID))
	require.EqualValues(t, lbls1.LabelArray(), owner.GetIdentity(id1a.ID))

	// reuse the same identity
	id1b, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	require.NotNil(t, id1b)
	require.False(t, isNew)
	require.NoError(t, err)
	require.Equal(t, id1b.ID, id1a.ID)

	released, err := mgr.Release(context.Background(), id1a, false)
	require.NoError(t, err)
	require.False(t, released)
	released, err = mgr.Release(context.Background(), id1b, false)
	require.NoError(t, err)
	require.Equal(t, true, released)
	// KV-store still keeps the ID even when a single node has released it.
	// This also means that we should have not received an event from the
	// KV-store for the deletion of the identity, so it should still be in
	// owner's cache.
	require.EqualValues(t, lbls1.LabelArray(), owner.GetIdentity(id1a.ID))

	id1b, isNew, err = mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	require.NotNil(t, id1b)
	require.NoError(t, err)
	// the value key should not have been removed so the same ID should be
	// assigned again and it should not be marked as new
	require.False(t, isNew)
	require.Equal(t, id1b.ID, id1a.ID)
	// Should still be cached, no new events should have been received.
	require.EqualValues(t, lbls1.LabelArray(), owner.GetIdentity(id1a.ID))

	ident := mgr.LookupIdentityByID(context.TODO(), id1b.ID)
	require.NotNil(t, ident)
	require.EqualValues(t, ident.Labels, lbls1)

	id2, isNew, err := mgr.AllocateIdentity(context.Background(), lbls2, false, identity.InvalidIdentity)
	require.NotNil(t, id2)
	require.Equal(t, true, isNew)
	require.NoError(t, err)
	require.NotEqual(t, id2.ID, id1a.ID)
	// Wait for the update event from the KV-store
	require.NotEqual(t, 0, owner.WaitUntilID(id2.ID))
	require.EqualValues(t, lbls2.LabelArray(), owner.GetIdentity(id2.ID))

	id3, isNew, err := mgr.AllocateIdentity(context.Background(), lbls3, false, identity.InvalidIdentity)
	require.NotNil(t, id3)
	require.Equal(t, true, isNew)
	require.NoError(t, err)
	require.NotEqual(t, id3.ID, id1a.ID)
	require.NotEqual(t, id3.ID, id2.ID)
	// Wait for the update event from the KV-store
	require.NotEqual(t, 0, owner.WaitUntilID(id3.ID))
	require.EqualValues(t, lbls3.LabelArray(), owner.GetIdentity(id3.ID))

	released, err = mgr.Release(context.Background(), id1b, false)
	require.NoError(t, err)
	require.Equal(t, true, released)
	released, err = mgr.Release(context.Background(), id2, false)
	require.NoError(t, err)
	require.Equal(t, true, released)
	released, err = mgr.Release(context.Background(), id3, false)
	require.NoError(t, err)
	require.Equal(t, true, released)

	mgr.IdentityAllocator.DeleteAllKeys()
	require.NotEqual(t, 0, owner.WaitUntilID(id3.ID))
}

func TestLocalAllocation(t *testing.T) {
	for _, be := range []string{"etcd", "consul"} {
		t.Run(be, func(t *testing.T) {
			testutils.IntegrationTest(t)
			kvstore.SetupDummy(t, be)
			testLocalAllocation(t)
		})
	}
}

func testLocalAllocation(t *testing.T) {
	lbls1 := labels.NewLabelsFromSortedList("cidr:192.0.2.3/32")

	owner := newDummyOwner()
	identity.InitWellKnownIdentities(fakeConfig, cmtypes.ClusterInfo{Name: "default", ID: 5})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(owner)
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()
	defer mgr.IdentityAllocator.DeleteAllKeys()

	id, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, true, identity.InvalidIdentity)
	require.NotNil(t, id)
	require.NoError(t, err)
	require.Equal(t, true, isNew)
	require.Equal(t, true, id.ID.HasLocalScope())
	// Wait for the update event from the KV-store
	require.NotEqual(t, 0, owner.WaitUntilID(id.ID))
	require.EqualValues(t, lbls1.LabelArray(), owner.GetIdentity(id.ID))

	// reuse the same identity
	id, isNew, err = mgr.AllocateIdentity(context.Background(), lbls1, true, identity.InvalidIdentity)
	require.NotNil(t, id)
	require.NoError(t, err)
	require.False(t, isNew)

	cache := mgr.GetIdentityCache()
	require.NotNil(t, cache[id.ID])

	// 1st Release, not released
	released, err := mgr.Release(context.Background(), id, true)
	require.NoError(t, err)
	require.False(t, released)

	// Identity still exists
	require.EqualValues(t, lbls1.LabelArray(), owner.GetIdentity(id.ID))

	// 2nd Release, released
	released, err = mgr.Release(context.Background(), id, true)
	require.NoError(t, err)
	require.Equal(t, true, released)

	// Wait until the identity is released
	require.NotEqual(t, 0, owner.WaitUntilID(id.ID))
	// Identity does not exist any more
	require.Nil(t, owner.GetIdentity(id.ID))

	cache = mgr.GetIdentityCache()
	require.Nil(t, cache[id.ID])

	id, isNew, err = mgr.AllocateIdentity(context.Background(), lbls1, true, identity.InvalidIdentity)
	require.NotNil(t, id)
	require.NoError(t, err)
	require.Equal(t, true, isNew)
	require.Equal(t, true, id.ID.HasLocalScope())

	released, err = mgr.Release(context.Background(), id, true)
	require.NoError(t, err)
	require.Equal(t, true, released)

	mgr.IdentityAllocator.DeleteAllKeys()
	require.NotEqual(t, 0, owner.WaitUntilID(id.ID))
}

func TestAllocatorReset(t *testing.T) {
	for _, be := range []string{"etcd", "consul"} {
		t.Run(be, func(t *testing.T) {
			testutils.IntegrationTest(t)
			kvstore.SetupDummy(t, be)
			testAllocatorReset(t)
		})
	}
}

// Test that we can close and reopen the allocator successfully.
func testAllocatorReset(t *testing.T) {
	labels := labels.NewLabelsFromSortedList("id=bar;user=anna")
	owner := newDummyOwner()
	mgr := NewCachingIdentityAllocator(owner)
	testAlloc := func() {
		id1a, _, err := mgr.AllocateIdentity(context.Background(), labels, false, identity.InvalidIdentity)
		require.NotNil(t, id1a)
		require.NoError(t, err)

		queued, ok := <-owner.updated
		require.Equal(t, true, ok)
		require.Equal(t, id1a.ID, queued)
	}

	<-mgr.InitIdentityAllocator(nil)
	testAlloc()
	mgr.Close()
	<-mgr.InitIdentityAllocator(nil)
	testAlloc()
	mgr.Close()
}

func TestAllocateLocally(t *testing.T) {
	mgr := NewCachingIdentityAllocator(newDummyOwner())

	cidrLbls := labels.NewLabelsFromSortedList("cidr:1.2.3.4/32")
	podLbls := labels.NewLabelsFromSortedList("k8s:foo=bar")

	assert.False(t, needsGlobalIdentity(cidrLbls))
	assert.True(t, needsGlobalIdentity(podLbls))

	id, allocated, err := mgr.AllocateLocalIdentity(cidrLbls, false, identity.IdentityScopeLocal+50)
	assert.Nil(t, err)
	assert.True(t, allocated)
	assert.Equal(t, id.ID.Scope(), identity.IdentityScopeLocal)
	assert.Equal(t, id.ID, identity.IdentityScopeLocal+50)

	id, _, err = mgr.AllocateLocalIdentity(podLbls, false, 0)
	assert.Error(t, err, ErrNonLocalIdentity)
	assert.Nil(t, id)
}

func TestCheckpointRestore(t *testing.T) {
	owner := newDummyOwner()
	mgr := NewCachingIdentityAllocator(owner)
	defer mgr.Close()
	dir := t.TempDir()
	mgr.checkpointPath = filepath.Join(dir, CheckpointFile)
	mgr.EnableCheckpointing()

	for _, l := range []string{
		"cidr:1.1.1.1/32;reserved:kube-apiserver",
		"cidr:1.1.1.2/32;reserved:kube-apiserver",
		"cidr:1.1.1.1/32",
		"cidr:1.1.1.2/32",
	} {
		lbls := labels.NewLabelsFromSortedList(l)
		assert.NotEqual(t, identity.IdentityScopeGlobal, identity.ScopeForLabels(lbls), "test bug: only restore locally-scoped labels")

		_, _, err := mgr.AllocateIdentity(context.Background(), lbls, false, 0)
		assert.Nil(t, err)
	}

	// ensure that the checkpoint file has been written
	// This is asynchronous, so we must retry
	assert.Eventually(t, func() bool {
		_, err := os.Stat(mgr.checkpointPath)
		return err == nil
	}, time.Second, 50*time.Millisecond)

	modelBefore := mgr.GetIdentities()

	// Explicitly checkpoint, to ensure we get the latest data
	err := mgr.checkpoint(context.TODO())
	require.NoError(t, err)

	newMgr := NewCachingIdentityAllocator(owner)
	defer newMgr.Close()
	newMgr.checkpointPath = mgr.checkpointPath

	restored, err := newMgr.RestoreLocalIdentities()
	assert.Nil(t, err)
	assert.Len(t, restored, 4)

	modelAfter := newMgr.GetIdentities()

	assert.ElementsMatch(t, modelBefore, modelAfter)
}

func TestClusterIDValidator(t *testing.T) {
	const (
		cid   = 5
		minID = cid << 16
		maxID = minID + 65535
	)

	var (
		validator = clusterIDValidator(cid)
		key       = &cacheKey.GlobalIdentity{}
	)

	// Identities matching the cluster ID should pass validation
	for _, id := range []idpool.ID{minID, minID + 1, maxID - 1, maxID} {
		assert.NoError(t, validator(allocator.AllocatorChangeUpsert, id, key), "ID %d should have passed validation", id)
	}

	// Identities not matching the cluster ID should fail validation
	for _, id := range []idpool.ID{1, minID - 1, maxID + 1} {
		assert.Error(t, validator(allocator.AllocatorChangeUpsert, id, key), "ID %d should have failed validation", id)
	}
}

func TestClusterNameValidator(t *testing.T) {
	const id = 100

	var (
		validator = clusterNameValidator("foo")
		generator = cacheKey.GlobalIdentity{}
	)

	key := generator.PutKey("k8s:foo=bar;k8s:bar=baz;qux=fred;k8s:io.cilium.k8s.policy.cluster=foo")
	assert.NoError(t, validator(allocator.AllocatorChangeUpsert, id, key))

	key = generator.PutKey("k8s:foo=bar;k8s:bar=baz")
	assert.EqualError(t, validator(allocator.AllocatorChangeUpsert, id, key), "could not find expected label io.cilium.k8s.policy.cluster")

	key = generator.PutKey("k8s:foo=bar;k8s:bar=baz;k8s:io.cilium.k8s.policy.cluster=bar")
	assert.EqualError(t, validator(allocator.AllocatorChangeUpsert, id, key), "unexpected cluster name: got bar, expected foo")

	key = generator.PutKey("k8s:foo=bar;k8s:bar=baz;qux:io.cilium.k8s.policy.cluster=bar")
	assert.EqualError(t, validator(allocator.AllocatorChangeUpsert, id, key), "unexpected source for cluster label: got qux, expected k8s")

	key = generator.PutKey("k8s:foo=bar;k8s:bar=baz;qux:io.cilium.k8s.policy.cluster=bar;k8s:io.cilium.k8s.policy.cluster=bar")
	assert.EqualError(t, validator(allocator.AllocatorChangeUpsert, id, key), "unexpected source for cluster label: got qux, expected k8s")

	assert.EqualError(t, validator(allocator.AllocatorChangeUpsert, id, nil), "unsupported key type <nil>")

	key = generator.PutKey("")
	assert.NoError(t, validator(allocator.AllocatorChangeDelete, id, key))
}
