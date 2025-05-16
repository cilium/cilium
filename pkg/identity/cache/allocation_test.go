// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/allocator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	cacheKey "github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	fakeConfig = &option.DaemonConfig{
		K8sNamespace: "kube-system",
	}

	testConfigs = []testConfig{
		{
			name: "disable_operator_manages_identities",
			allocatorConfig: AllocatorConfig{
				EnableOperatorManageCIDs: false,
			},
		},
		{
			name: "enable_operator_manages_identities",
			allocatorConfig: AllocatorConfig{
				EnableOperatorManageCIDs: true,
			},
		},
	}
)

type testConfig struct {
	name            string
	allocatorConfig AllocatorConfig
}

func TestAllocateIdentityReserved(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	for _, testConfig := range testConfigs {
		t.Run(testConfig.name, func(t *testing.T) {
			testAllocateIdentityReserved(t, testConfig)
		})
	}
}

func testAllocateIdentityReserved(t *testing.T, testConfig testConfig) {
	var (
		lbls  labels.Labels
		i     *identity.Identity
		isNew bool
		err   error
	)

	logger := hivetest.Logger(t)

	lbls = labels.Labels{
		labels.IDNameHost: labels.NewLabel(labels.IDNameHost, "", labels.LabelSourceReserved),
	}

	mgr := NewCachingIdentityAllocator(logger, newDummyOwner(logger), testConfig.allocatorConfig)
	<-mgr.InitIdentityAllocator(nil)

	require.True(t, identity.IdentityAllocationIsLocal(lbls))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityHost, i.ID)
	require.False(t, isNew)

	lbls = labels.Labels{
		labels.IDNameWorld: labels.NewLabel(labels.IDNameWorld, "", labels.LabelSourceReserved),
	}
	require.True(t, identity.IdentityAllocationIsLocal(lbls))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityWorld, i.ID)
	require.False(t, isNew)

	require.True(t, identity.IdentityAllocationIsLocal(labels.LabelHealth))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), labels.LabelHealth, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityHealth, i.ID)
	require.False(t, isNew)

	lbls = labels.Labels{
		labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
	}
	require.True(t, identity.IdentityAllocationIsLocal(lbls))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityInit, i.ID)
	require.False(t, isNew)

	lbls = labels.Labels{
		labels.IDNameUnmanaged: labels.NewLabel(labels.IDNameUnmanaged, "", labels.LabelSourceReserved),
	}
	require.True(t, identity.IdentityAllocationIsLocal(lbls))
	i, isNew, err = mgr.AllocateIdentity(context.Background(), lbls, false, identity.InvalidIdentity)
	require.NoError(t, err)
	require.Equal(t, identity.ReservedIdentityUnmanaged, i.ID)
	require.False(t, isNew)
}

type dummyOwner struct {
	logger  *slog.Logger
	updated chan identity.NumericIdentity
	mutex   lock.Mutex
	cache   identity.IdentityMap
}

func newDummyOwner(logger *slog.Logger) *dummyOwner {
	return &dummyOwner{
		logger:  logger,
		cache:   identity.IdentityMap{},
		updated: make(chan identity.NumericIdentity, 1024),
	}
}

func (d *dummyOwner) UpdateIdentities(added, deleted identity.IdentityMap) {
	d.mutex.Lock()
	d.logger.Debug(fmt.Sprintf("Dummy UpdateIdentities(added: %v, deleted: %v)", added, deleted))
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

func TestEventWatcherBatching(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	testEventWatcherBatching(t)
}

func testEventWatcherBatching(t *testing.T) {
	logger := hivetest.Logger(t)
	owner := newDummyOwner(logger)
	events := make(allocator.AllocatorEventChan, 1024)
	watcher := identityWatcher{
		logger: logger,
		owner:  owner,
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
	require.Equal(t, lbls.LabelArray(), owner.GetIdentity(identity.NumericIdentity(1033)))
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

func TestAllocator(t *testing.T) {
	testutils.IntegrationTest(t)
	cl := kvstore.SetupDummy(t, "etcd")
	testAllocator(t)
	testAllocatorOperatorIDManagement(t, kvstoreClient{cl})
}

func testAllocator(t *testing.T) {
	logger := hivetest.Logger(t)
	lbls1 := labels.NewLabelsFromSortedList("blah=%%//!!;id=foo;user=anna")
	lbls2 := labels.NewLabelsFromSortedList("id=bar;user=anna")
	lbls3 := labels.NewLabelsFromSortedList("id=bar;user=susan")

	owner := newDummyOwner(logger)
	identity.InitWellKnownIdentities(fakeConfig, cmtypes.ClusterInfo{Name: "default", ID: 5})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(logger, owner, AllocatorConfig{EnableOperatorManageCIDs: false})
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()
	defer mgr.IdentityAllocator.DeleteAllKeys()

	id1a, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	require.NotNil(t, id1a)
	require.NoError(t, err)
	require.True(t, isNew)
	// Wait for the update event from the KV-store
	require.NotEqual(t, 0, owner.WaitUntilID(id1a.ID))
	require.Equal(t, lbls1.LabelArray(), owner.GetIdentity(id1a.ID))

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
	require.True(t, released)
	// KV-store still keeps the ID even when a single node has released it.
	// This also means that we should have not received an event from the
	// KV-store for the deletion of the identity, so it should still be in
	// owner's cache.
	require.Equal(t, lbls1.LabelArray(), owner.GetIdentity(id1a.ID))

	id1b, isNew, err = mgr.AllocateIdentity(context.Background(), lbls1, false, identity.InvalidIdentity)
	require.NotNil(t, id1b)
	require.NoError(t, err)
	// the value key should not have been removed so the same ID should be
	// assigned again and it should not be marked as new
	require.False(t, isNew)
	require.Equal(t, id1b.ID, id1a.ID)
	// Should still be cached, no new events should have been received.
	require.Equal(t, lbls1.LabelArray(), owner.GetIdentity(id1a.ID))

	ident := mgr.LookupIdentityByID(context.TODO(), id1b.ID)
	require.NotNil(t, ident)
	require.Equal(t, ident.Labels, lbls1)

	id2, isNew, err := mgr.AllocateIdentity(context.Background(), lbls2, false, identity.InvalidIdentity)
	require.NotNil(t, id2)
	require.True(t, isNew)
	require.NoError(t, err)
	require.NotEqual(t, id2.ID, id1a.ID)
	// Wait for the update event from the KV-store
	require.NotEqual(t, 0, owner.WaitUntilID(id2.ID))
	require.Equal(t, lbls2.LabelArray(), owner.GetIdentity(id2.ID))

	id3, isNew, err := mgr.AllocateIdentity(context.Background(), lbls3, false, identity.InvalidIdentity)
	require.NotNil(t, id3)
	require.True(t, isNew)
	require.NoError(t, err)
	require.NotEqual(t, id3.ID, id1a.ID)
	require.NotEqual(t, id3.ID, id2.ID)
	// Wait for the update event from the KV-store
	require.NotEqual(t, 0, owner.WaitUntilID(id3.ID))
	require.Equal(t, lbls3.LabelArray(), owner.GetIdentity(id3.ID))

	released, err = mgr.Release(context.Background(), id1b, false)
	require.NoError(t, err)
	require.True(t, released)
	released, err = mgr.Release(context.Background(), id2, false)
	require.NoError(t, err)
	require.True(t, released)
	released, err = mgr.Release(context.Background(), id3, false)
	require.NoError(t, err)
	require.True(t, released)

	mgr.IdentityAllocator.DeleteAllKeys()
	require.NotEqual(t, 0, owner.WaitUntilID(id3.ID))
}

func createCIDObj(id string, lbls labels.Labels) *capi_v2.CiliumIdentity {
	k := &cacheKey.GlobalIdentity{LabelArray: lbls.LabelArray()}
	selectedLabels := identitybackend.SelectK8sLabels(k.GetAsMap())
	return &capi_v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   id,
			Labels: selectedLabels,
		},
		SecurityLabels: k.GetAsMap(),
	}
}

func testAllocatorOperatorIDManagement(t *testing.T, cl kvstoreClient) {
	const testNamePrefix = "operator_id_management"

	type testCase struct {
		name           string
		allocationMode string
	}

	testCases := []testCase{
		{
			name:           "kvstore_id",
			allocationMode: option.IdentityAllocationModeKVstore,
		},
		{
			name:           "crd_id",
			allocationMode: option.IdentityAllocationModeCRD,
		},
		{
			name:           "kvstore_double_wr_id",
			allocationMode: option.IdentityAllocationModeDoubleWriteReadKVstore,
		},
		{
			name:           "crd_double_wr_id",
			allocationMode: option.IdentityAllocationModeDoubleWriteReadCRD,
		},
	}

	for _, tc := range testCases {
		testName := fmt.Sprintf("%s_%s", testNamePrefix, tc.name)
		t.Run(testName, func(t *testing.T) {
			logger := hivetest.Logger(t)
			option.Config.IdentityAllocationMode = tc.allocationMode
			defer func() { option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore }()

			lbls1 := labels.NewLabelsFromSortedList("blah=%%//!!;id=foo;user=anna")

			ctx := context.Background()
			_, kubeClient := k8sClient.NewFakeClientset(logger)

			owner := newDummyOwner(logger)
			identity.InitWellKnownIdentities(fakeConfig, cmtypes.ClusterInfo{Name: "default", ID: 5})
			mgr := NewCachingIdentityAllocator(logger, owner, AllocatorConfig{EnableOperatorManageCIDs: true, maxAllocAttempts: 2})
			<-mgr.InitIdentityAllocator(kubeClient)
			defer mgr.Close()
			defer mgr.IdentityAllocator.DeleteAllKeys()

			// Verify that allocating an identity that doesn't exist will return an error.
			id1a, isNew, err := mgr.AllocateIdentity(ctx, lbls1, false, identity.InvalidIdentity)
			require.Nil(t, id1a)
			require.Error(t, err)
			require.False(t, isNew)

			id := createCIDObj("1000", lbls1)

			var err2 error
			switch option.Config.IdentityAllocationMode {
			case option.IdentityAllocationModeKVstore:
				err = cl.addIDKVStore(ctx, id.Name, lbls1)
			case option.IdentityAllocationModeCRD:
				_, err = kubeClient.CiliumV2().CiliumIdentities().Create(ctx, id, metav1.CreateOptions{})
			case option.IdentityAllocationModeDoubleWriteReadKVstore, option.IdentityAllocationModeDoubleWriteReadCRD:
				err2 = cl.addIDKVStore(ctx, id.Name, lbls1)
				_, err = kubeClient.CiliumV2().CiliumIdentities().Create(ctx, id, metav1.CreateOptions{})
			}
			require.NoError(t, err)
			require.NoError(t, err2)

			// Verify that the created CID is allocated, as an existing CID in the store.
			var id2 *identity.Identity
			err = testutils.WaitUntil(func() bool {
				id2, isNew, err2 = mgr.AllocateIdentity(ctx, lbls1, false, identity.InvalidIdentity)
				return id2 != nil && err2 == nil
			}, 100*time.Millisecond)
			require.NoError(t, err)
			require.False(t, isNew)
			require.Equal(t, lbls1.LabelArray(), id2.LabelArray)

			// Repeat verification for the same lbls.
			var id3 *identity.Identity
			err = testutils.WaitUntil(func() bool {
				id3, isNew, err2 = mgr.AllocateIdentity(ctx, lbls1, false, identity.InvalidIdentity)
				return id3 != nil && err2 == nil
			}, 100*time.Millisecond)
			require.NoError(t, err)
			require.False(t, isNew)
			require.Equal(t, lbls1.LabelArray(), id3.LabelArray)

			released, err := mgr.Release(ctx, id2, false)
			require.NoError(t, err)
			require.False(t, released)

			switch option.Config.IdentityAllocationMode {
			case option.IdentityAllocationModeKVstore:
				err = cl.removeIDKVStore(ctx, id.Name)
			case option.IdentityAllocationModeCRD:
				err = kubeClient.CiliumV2().CiliumIdentities().Delete(ctx, id.Name, metav1.DeleteOptions{})
			case option.IdentityAllocationModeDoubleWriteReadKVstore, option.IdentityAllocationModeDoubleWriteReadCRD:
				err = cl.removeIDKVStore(ctx, id.Name)
				err2 = kubeClient.CiliumV2().CiliumIdentities().Delete(ctx, id.Name, metav1.DeleteOptions{})
			}
			require.NoError(t, err)
			require.NoError(t, err2)

			// Verify that allocating an identity that doesn't exist will return an error
			// after deleting the id from the store.
			var id4 *identity.Identity
			err = testutils.WaitUntil(func() bool {
				id4, isNew, err2 = mgr.AllocateIdentity(ctx, lbls1, false, identity.InvalidIdentity)
				return id4 == nil && err2 != nil
			}, 100*time.Millisecond)
			require.NoError(t, err)
			require.False(t, isNew)

			released, err = mgr.Release(ctx, id2, false)
			require.NoError(t, err)
			require.False(t, released)
		})
	}

}

type kvstoreClient struct{ kvstore.BackendOperations }

func (c *kvstoreClient) addIDKVStore(ctx context.Context, id string, lbls labels.Labels) error {
	key := &cacheKey.GlobalIdentity{LabelArray: lbls.LabelArray()}
	idPrefix := path.Join(IdentitiesPath, "id")
	keyPath := path.Join(idPrefix, id)
	success, err := c.CreateOnly(ctx, keyPath, []byte(key.GetKey()), false)
	if err != nil || !success {
		return fmt.Errorf("unable to create master key '%s': %w", keyPath, err)
	}
	return nil
}

func (c *kvstoreClient) removeIDKVStore(ctx context.Context, id string) error {
	prefix := path.Join(IdentitiesPath, "id")
	key := path.Join(prefix, id)
	return c.Delete(ctx, key)
}

func TestLocalAllocation(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	for _, testConfig := range testConfigs {
		t.Run(testConfig.name, func(t *testing.T) {
			testLocalAllocation(t, testConfig)
		})
	}
}

func testLocalAllocation(t *testing.T, testConfig testConfig) {
	lbls1 := labels.NewLabelsFromSortedList("cidr:192.0.2.3/32")
	logger := hivetest.Logger(t)

	owner := newDummyOwner(logger)
	identity.InitWellKnownIdentities(fakeConfig, cmtypes.ClusterInfo{Name: "default", ID: 5})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(logger, owner, testConfig.allocatorConfig)
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()
	defer mgr.IdentityAllocator.DeleteAllKeys()

	id, isNew, err := mgr.AllocateIdentity(context.Background(), lbls1, true, identity.InvalidIdentity)
	require.NotNil(t, id)
	require.NoError(t, err)
	require.True(t, isNew)
	require.True(t, id.ID.HasLocalScope())
	// Wait for the update event from the KV-store
	require.NotEqual(t, 0, owner.WaitUntilID(id.ID))
	require.Equal(t, lbls1.LabelArray(), owner.GetIdentity(id.ID))

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
	require.Equal(t, lbls1.LabelArray(), owner.GetIdentity(id.ID))

	// 2nd Release, released
	released, err = mgr.Release(context.Background(), id, true)
	require.NoError(t, err)
	require.True(t, released)

	// Wait until the identity is released
	require.NotEqual(t, 0, owner.WaitUntilID(id.ID))
	// Identity does not exist any more
	require.Nil(t, owner.GetIdentity(id.ID))

	cache = mgr.GetIdentityCache()
	require.Nil(t, cache[id.ID])

	id, isNew, err = mgr.AllocateIdentity(context.Background(), lbls1, true, identity.InvalidIdentity)
	require.NotNil(t, id)
	require.NoError(t, err)
	require.True(t, isNew)
	require.True(t, id.ID.HasLocalScope())

	released, err = mgr.Release(context.Background(), id, true)
	require.NoError(t, err)
	require.True(t, released)

	mgr.IdentityAllocator.DeleteAllKeys()
	require.NotEqual(t, 0, owner.WaitUntilID(id.ID))
}

func TestAllocatorReset(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	for _, testConfig := range testConfigs {
		t.Run(testConfig.name, func(t *testing.T) {
			testAllocatorReset(t, testConfig)
		})
	}
}

// Test that we can close and reopen the allocator successfully.
func testAllocatorReset(t *testing.T, testConfig testConfig) {
	labels := labels.NewLabelsFromSortedList("id=bar;user=anna")
	logger := hivetest.Logger(t)
	owner := newDummyOwner(logger)
	mgr := NewCachingIdentityAllocator(logger, owner, testConfig.allocatorConfig)
	testAlloc := func() {
		id1a, _, err := mgr.AllocateIdentity(context.Background(), labels, false, identity.InvalidIdentity)
		require.NotNil(t, id1a)
		require.NoError(t, err)

		queued, ok := <-owner.updated
		require.True(t, ok)
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
	for _, testConfig := range testConfigs {
		t.Run(testConfig.name, func(t *testing.T) {
			testAllocateLocally(t, testConfig)
		})
	}
}

func testAllocateLocally(t *testing.T, testConfig testConfig) {
	logger := hivetest.Logger(t)
	mgr := NewCachingIdentityAllocator(logger, newDummyOwner(logger), testConfig.allocatorConfig)

	cidrLbls := labels.NewLabelsFromSortedList("cidr:1.2.3.4/32")
	podLbls := labels.NewLabelsFromSortedList("k8s:foo=bar")
	ingressLbls := labels.NewLabelsFromSortedList("reserved:ingress;k8s:foo=bar")

	assert.False(t, needsGlobalIdentity(cidrLbls))
	assert.True(t, needsGlobalIdentity(podLbls))
	assert.False(t, needsGlobalIdentity(ingressLbls))

	id, allocated, err := mgr.AllocateLocalIdentity(cidrLbls, false, identity.IdentityScopeLocal+50)
	assert.NoError(t, err)
	assert.True(t, allocated)
	assert.Equal(t, identity.IdentityScopeLocal, id.ID.Scope())
	assert.Equal(t, identity.IdentityScopeLocal+50, id.ID)

	id, _, err = mgr.AllocateLocalIdentity(podLbls, false, 0)
	assert.ErrorIs(t, err, ErrNonLocalIdentity)
	assert.Nil(t, id)

	id, _, err = mgr.AllocateLocalIdentity(ingressLbls, false, 0)
	assert.NoError(t, err)
	assert.True(t, allocated)
	assert.Equal(t, identity.IdentityScopeLocal, id.ID.Scope())
	assert.Equal(t, identity.IdentityScopeLocal+1, id.ID)
}

func TestCheckpointRestore(t *testing.T) {
	for _, testConfig := range testConfigs {
		t.Run(testConfig.name, func(t *testing.T) {
			testCheckpointRestore(t, testConfig)
		})
	}
}

func testCheckpointRestore(t *testing.T, testConfig testConfig) {
	logger := hivetest.Logger(t)
	owner := newDummyOwner(logger)
	mgr := NewCachingIdentityAllocator(logger, owner, testConfig.allocatorConfig)
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
		assert.NoError(t, err)
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

	newMgr := NewCachingIdentityAllocator(logger, owner, AllocatorConfig{})
	defer newMgr.Close()
	newMgr.checkpointPath = mgr.checkpointPath

	restored, err := newMgr.RestoreLocalIdentities()
	assert.NoError(t, err)
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
