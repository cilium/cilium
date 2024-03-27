// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nonglobal

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/completion"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	idcache "github.com/cilium/cilium/pkg/identity/cache"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	testLblsArray labels.LabelArray
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
	l := NewLocalOnlyCachingIDAllocator(ctx, owner, ciliumIdentity, testGCEndpointListerFunc)
	l.InitIdentityAllocator(nil)

	testAllocateAndReleaseIdentity(ctx, t, l)
	testGetIDCacheAndModel(ctx, t, l)
	testLookupIdentity(ctx, t, l)
	testEndpointReconcliation(t, l)

	allocator, err := l.WatchRemoteIdentities("", nil, false)
	assert.Nil(t, allocator)
	assert.Error(t, err)

	testIdentityObserve(ctx, t, l)

	l.Close()

	l = NewLocalOnlyCachingIDAllocator(ctx, owner, ciliumIdentity, testGCEndpointListerFunc)
	l.InitIdentityAllocator(nil)
	testAllocatorControllerRestart(ctx, t, l)

	l.Close()
}

func testAllocateAndReleaseIdentity(ctx context.Context, t *testing.T, l *LocalOnlyCachingIDAllocator) {
	id1, allocated, err := l.AllocateIdentity(ctx, testLblsA, false, identity.InvalidIdentity)
	assert.NoError(t, err)
	assert.Equal(t, true, allocated)
	assert.Equal(t, testLblsA, id1.Labels)

	id2, allocated, err := l.AllocateIdentity(ctx, testLblsA, false, id1.ID)
	assert.NoError(t, err)
	assert.Equal(t, false, allocated)
	assert.Equal(t, id1, id2)

	released, err := l.Release(ctx, id2, false)
	assert.NoError(t, err)
	assert.Equal(t, false, released)

	err = l.ReleaseSlice(ctx, []*identity.Identity{id1, id2})
	assert.NoError(t, err)
}

func testGetIDCacheAndModel(ctx context.Context, t *testing.T, l *LocalOnlyCachingIDAllocator) {
	cidStore, _ := l.ciliumIdentities.Store(ctx)

	numID2 := identity.NumericIdentity(1000)
	idCache := l.GetIdentityCache()
	lblsArray, exists := idCache[numID2]
	assert.Equal(t, false, exists)
	assert.Equal(t, testLblsArray, lblsArray)

	idModel := l.GetIdentities()
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
	cidStore.CacheStore().Add(cid1)

	idCache = l.GetIdentityCache()
	lblsArray, exists = idCache[numID2]
	assert.Equal(t, true, exists)
	assert.Equal(t, testLblsB.LabelArray(), lblsArray)

	idModel = l.GetIdentities()
	foundID := false
	for _, id := range idModel {
		if numID2 == identity.NumericIdentity(id.ID) {
			foundID = true
			break
		}
	}
	assert.Equal(t, true, foundID)
}

func testLookupIdentity(ctx context.Context, t *testing.T, l *LocalOnlyCachingIDAllocator) {
	cidStore, _ := l.ciliumIdentities.Store(ctx)

	id1, allocated, err := l.AllocateIdentity(ctx, testLblsA, false, identity.InvalidIdentity)
	assert.NoError(t, err)
	assert.Equal(t, false, allocated, "already allocated in previous test func")
	assert.Equal(t, testLblsA, id1.Labels)

	id := l.LookupIdentity(ctx, testLblsA)
	assert.Equal(t, id1, id)

	id = l.LookupIdentityByID(ctx, id1.ID)
	assert.Equal(t, id1, id)

	id = l.LookupIdentity(ctx, labels.LabelHost)
	assert.NotNil(t, id)
	assert.Equal(t, identity.NumericIdentity(1), id.ID, "Reserved ID")

	id = l.LookupIdentity(ctx, testLblsB)
	assert.NotNil(t, id)
	assert.Equal(t, 1000, int(id.ID), "ID from watcher store")

	id = l.LookupIdentityByID(ctx, identity.NumericIdentity(5000))
	assert.Equal(t, nilID, id, "Non existant ID")

	id = l.LookupIdentityByID(ctx, identity.IdentityUnknown)
	_, exists := id.Labels[labels.IDNameUnknown]
	assert.Equal(t, true, exists, "Unknown ID")

	id = l.LookupIdentityByID(ctx, identity.NumericIdentity(1000))
	assert.Equal(t, testLblsB, id.Labels, "ID from watcher store")

	id = l.LookupIdentityByID(ctx, identity.NumericIdentity(1))
	assert.Equal(t, labels.LabelHost, id.Labels, "Reserved ID")

	id = l.LookupIdentityByID(ctx, identity.NumericIdentity(1<<24))
	assert.Equal(t, nilID, id, "Local ID")

	numID2 := identity.NumericIdentity(900)
	cid2 := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   numID2.String(),
			Labels: testLblsB.StringMap(),
		},
		SecurityLabels: testLblsB.StringMap(),
	}
	cidStore.CacheStore().Add(cid2)

	id = l.LookupIdentity(ctx, testLblsB)
	assert.Equal(t, numID2, id.ID, "ID from watcher store")
}

func testEndpointReconcliation(t *testing.T, l *LocalOnlyCachingIDAllocator) {
	localEps := []*endpoint.Endpoint{}
	listEpsFunc := func() []*endpoint.Endpoint { return localEps }
	l.tempIDAllocator = NewTempSecIDAllocator(listEpsFunc)

	allocExt := testAllocatorExtended{l}
	epMgr := testEndpointManager{repo: policy.NewPolicyRepository(allocExt, nil, nil, nil)}
	for id := 1; id <= 10; id++ {
		ep := endpoint.NewEndpointWithState(epMgr, epMgr, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(id), endpoint.StateReady)
		ep.OpLabels = labels.NewOpLabels()
		ep.OpLabels.Custom = testLblsA
		localEps = append(localEps, ep)
	}

	l.ValidateEndpointIDForCIDEvent(localEps)
	waitForEpQueueToBeEmpty(l)
	assert.Equal(t, 1, len(l.tempIDAllocator.tempIDCache.idToIdentity), "One temp id created for endpoints")

	l.ValidateEndpointIDForCIDEvent(localEps)
	waitForEpQueueToBeEmpty(l)
	assert.Equal(t, 1, len(l.tempIDAllocator.tempIDCache.idToIdentity), "Still one temp id exists for endpoints")

	localEps[0].OpLabels.Custom = testLblsB
	l.ValidateEndpointIDForCIDEvent(localEps)
	waitForEpQueueToBeEmpty(l)
	assert.Equal(t, 2, len(l.tempIDAllocator.tempIDCache.idToIdentity), "One more temp id created for endpoints, after changing one endpoint's labels")

	localEps[1] = nil
	localEps[2].OpLabels.Custom = testLblsC
	l.ValidateEndpointIDForCIDEvent(localEps)
	waitForEpQueueToBeEmpty(l)
	assert.Equal(t, 3, len(l.tempIDAllocator.tempIDCache.idToIdentity), "One more temp id created for endpoints, after changing one endpoint's labels")
}

func testAllocatorControllerRestart(ctx context.Context, t *testing.T, l *LocalOnlyCachingIDAllocator) {
	id := l.LookupIdentity(ctx, testLblsB)
	assert.NotNil(t, id)
	assert.Equal(t, 900, int(id.ID), "ID from watcher store")
}

func testIdentityObserve(ctx context.Context, t *testing.T, l *LocalOnlyCachingIDAllocator) {
	var lastChange idcache.IdentityChange
	l.Observe(ctx, func(change idcache.IdentityChange) {
		lastChange = change
	}, func(error) {})
	assert.Equal(t, identity.IdentityUnknown, lastChange.ID)
}

func waitForEpQueueToBeEmpty(l *LocalOnlyCachingIDAllocator) {
	for l.endpointQueue.Len() > 0 {
		time.Sleep(5 * time.Millisecond)
	}
}

type testEndpointManager struct {
	repo *policy.Repository
}

func (s testEndpointManager) GetPolicyRepository() *policy.Repository {
	return s.repo
}

func (s testEndpointManager) UpdateProxyRedirect(e regeneration.EndpointUpdater, l4 *policy.L4Filter, wg *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	return 0, nil, nil, nil
}

func (s testEndpointManager) RemoveProxyRedirect(e regeneration.EndpointInfoSource, id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

func (s testEndpointManager) UpdateNetworkPolicy(e regeneration.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy,
	proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	return nil, nil
}

func (s testEndpointManager) RemoveNetworkPolicy(e regeneration.EndpointInfoSource) {}

func (s testEndpointManager) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s testEndpointManager) GetCompilationLock() *lock.RWMutex {
	return nil
}

func (s testEndpointManager) GetCIDRPrefixLengths() (s6, s4 []int) {
	return nil, nil
}

func (s testEndpointManager) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	return nil
}

func (s testEndpointManager) Datapath() datapath.Datapath {
	return nil
}

func (s testEndpointManager) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s testEndpointManager) RemoveRestoredDNSRules(epID uint16) {
}

type testAllocatorExtended struct {
	*LocalOnlyCachingIDAllocator
}

func (l testAllocatorExtended) AllocateCIDRsForIPs(ips []net.IP, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity) ([]*identity.Identity, error) {
	return nil, nil
}

func (l testAllocatorExtended) ReleaseCIDRIdentitiesByID(ctx context.Context, identities []identity.NumericIdentity) {
}
