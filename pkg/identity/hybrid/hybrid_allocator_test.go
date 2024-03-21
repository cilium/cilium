// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hybrid

import (
	"context"
	"testing"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	idcache "github.com/cilium/cilium/pkg/identity/cache"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	testLblsArray labels.LabelArray

	testIDAllocatorGC cache.IdentityAllocator

	testLblsA    = labels.Map2Labels(map[string]string{"key-a": "val-1"}, labels.LabelSourceK8s)
	testLblsB    = labels.Map2Labels(map[string]string{"key-b": "val-2"}, labels.LabelSourceK8s)
	testLblsC    = labels.Map2Labels(map[string]string{"key-c": "val-3"}, labels.LabelSourceK8s)
	testNumOfEps = 10

	nilID   *identity.Identity
	testEps []*endpoint.Endpoint
)

func TestLocalOnlyAllocator(t *testing.T) {
	var ciliumIdentity resource.Resource[*capi_v2.CiliumIdentity]
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cidResource resource.Resource[*capi_v2.CiliumIdentity],
		) error {
			ciliumIdentity = cidResource
			return nil
		}),
	)

	ctx := context.Background()
	hive.Start(ctx)
	defer func() {
		hive.Stop(ctx)
	}()

	owner := idcache.NewDummyOwner()
	h := NewHybridIDAllocator(ctx, owner, ciliumIdentity)
	h.InitIdentityAllocator(nil)

	testAllocateAndReleaseIdentity(ctx, t, h)
	testGetIDCacheAndModel(t, h)
	testLookupIdentity(ctx, t, h)

	allocator, err := h.WatchRemoteIdentities("", nil, false)
	assert.Nil(t, allocator)
	assert.Error(t, err)

	testIdentityObserve(ctx, t, h)

	h.Close()
}

func testAllocateAndReleaseIdentity(ctx context.Context, t *testing.T, h *HybridIDAllocator) {
	numID1 := identity.NumericIdentity(500)
	cid1 := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   numID1.String(),
			Labels: testLblsA.StringMap(),
		},
		SecurityLabels: testLblsA.StringMap(),
	}
	cidStore, _ := h.ciliumIdentities.Store(h.ctx)
	cidStore.CacheStore().Add(cid1)

	id1, allocated, err := h.AllocateIdentity(ctx, testLblsA, false, identity.InvalidIdentity)
	assert.NoError(t, err)
	assert.Equal(t, true, allocated)
	assert.Equal(t, testLblsA, id1.Labels)

	released, err := h.Release(ctx, id1, false)
	assert.NoError(t, err)
	assert.Equal(t, false, released)

	err = h.ReleaseSlice(ctx, nil, []*identity.Identity{id1})
	assert.NoError(t, err)
}

func testGetIDCacheAndModel(t *testing.T, h *HybridIDAllocator) {
	numID2 := identity.NumericIdentity(1000)
	idCache := h.GetIdentityCache()
	lblsArray, exists := idCache[numID2]
	assert.Equal(t, false, exists)
	assert.Equal(t, testLblsArray, lblsArray)

	idModel := h.GetIdentities()
	for _, id := range idModel {
		assert.NotEqual(t, numID2, id.ID)
	}

	cid1 := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   numID2.String(),
			Labels: testLblsB.StringMap(),
		},
		SecurityLabels: testLblsB.StringMap(),
	}
	cidStore, _ := h.ciliumIdentities.Store(h.ctx)
	cidStore.CacheStore().Add(cid1)
	idCache = h.GetIdentityCache()
	lblsArray, exists = idCache[numID2]
	assert.Equal(t, true, exists)
	assert.Equal(t, testLblsB.LabelArray(), lblsArray)

	idModel = h.GetIdentities()
	for _, id := range idModel {
		assert.NotEqual(t, numID2, id.ID)
	}

	idCache = h.GetIdentityCache()
	lblsArray, exists = idCache[numID2]
	assert.Equal(t, true, exists)
	assert.Equal(t, testLblsB.LabelArray(), lblsArray)

	idModel = h.GetIdentities()
	foundID := false
	for _, id := range idModel {
		if numID2 == identity.NumericIdentity(id.ID) {
			foundID = true
			break
		}
	}
	assert.Equal(t, true, foundID)
}

func testLookupIdentity(ctx context.Context, t *testing.T, h *HybridIDAllocator) {
	id1, allocated, err := h.AllocateIdentity(ctx, testLblsA, false, identity.InvalidIdentity)
	assert.NoError(t, err)
	assert.Equal(t, true, allocated)
	assert.Equal(t, testLblsA, id1.Labels)

	id := h.LookupIdentity(ctx, testLblsA)
	assert.Equal(t, id1, id)

	id = h.LookupIdentityByID(ctx, id1.ID)
	assert.Equal(t, id1, id)

	id = h.LookupIdentity(ctx, labels.LabelHost)
	assert.Equal(t, identity.NumericIdentity(1), id.ID, "Reserved ID")

	id = h.LookupIdentity(ctx, testLblsB)
	assert.Equal(t, identity.NumericIdentity(1000), id.ID, "ID from watcher store")

	id = h.LookupIdentityByID(ctx, identity.NumericIdentity(5000))
	assert.Equal(t, nilID, id, "Non existant ID")

	id = h.LookupIdentityByID(ctx, identity.IdentityUnknown)
	_, exists := id.Labels[labels.IDNameUnknown]
	assert.Equal(t, true, exists, "Unknown ID")

	id = h.LookupIdentityByID(ctx, identity.NumericIdentity(1000))
	assert.Equal(t, testLblsB, id.Labels, "ID from watcher store")

	id = h.LookupIdentityByID(ctx, identity.NumericIdentity(1))
	assert.Equal(t, labels.LabelHost, id.Labels, "Reserved ID")

	id = h.LookupIdentityByID(ctx, identity.NumericIdentity(1<<24))
	assert.Equal(t, nilID, id, "Local ID")

	numID2 := identity.NumericIdentity(900)
	cid2 := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   numID2.String(),
			Labels: testLblsB.StringMap(),
		},
		SecurityLabels: testLblsB.StringMap(),
	}
	cidStore, _ := h.ciliumIdentities.Store(h.ctx)
	cidStore.CacheStore().Add(cid2)

	id = h.LookupIdentity(ctx, testLblsB)
	assert.Equal(t, numID2, id.ID, "ID from watcher store")
}

func testIdentityObserve(ctx context.Context, t *testing.T, h *HybridIDAllocator) {
	var lastChange idcache.IdentityChange
	h.Observe(ctx, func(change idcache.IdentityChange) {
		lastChange = change
	}, func(error) {})
	assert.Equal(t, identity.IdentityUnknown, lastChange.ID)
}
