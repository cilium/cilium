// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

var (
	worldPrefix     = netip.MustParsePrefix("1.1.1.1/32")
	inClusterPrefix = netip.MustParsePrefix("10.0.0.4/32")
	aPrefix         = netip.MustParsePrefix("100.4.16.32/32")
)

func TestInjectLabels(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	updater := IPIdentityCache.PolicyHandler.(*mockUpdater)
	allocator := IPIdentityCache.IdentityAllocator.(*testidentity.MockIdentityAllocator)

	assert.Len(t, IPIdentityCache.metadata.m, 1)
	remaining, err := IPIdentityCache.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.Len(t, remaining, 0)
	assert.NoError(t, err)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	id := IPIdentityCache.ipToIdentityCache[worldPrefix.String()].ID
	assert.Len(t, updater.added, 1)
	assert.Equal(t, allocator.LookupIdentityByID(ctx, id).LabelArray, updater.added[id])
	assert.Len(t, updater.removed, 0)

	// Insert kube-apiserver IP from outside of the cluster. This should create
	// a CIDR ID for this IP.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.True(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())

	id = IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID
	assert.Len(t, updater.added, 1)
	assert.Equal(t, allocator.LookupIdentityByID(ctx, id).Labels.LabelArray(), updater.added[id])
	assert.Len(t, updater.removed, 0)

	// Upsert node labels to the kube-apiserver to validate that the CIDR ID is
	// deallocated and the kube-apiserver reserved ID is associated with this
	// IP now.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid", labels.LabelRemoteNode)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())

	assert.Len(t, updater.added, 0)
	assert.Len(t, updater.removed, 1)
	assert.Contains(t, updater.removed, id)

	// Assert that a CIDR identity can be overridden automatically (without
	// overrideIdentity=true) when the prefix becomes associated with an entity
	// within the cluster.
	IPIdentityCache.metadata.upsertLocked(aPrefix, source.Generated, "cnp-uid", labels.LabelWorld)
	assert.Len(t, IPIdentityCache.metadata.m, 3)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{aPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	assert.True(t, IPIdentityCache.ipToIdentityCache["100.4.16.32/32"].ID.HasLocalScope())
	IPIdentityCache.metadata.upsertLocked(aPrefix, source.CustomResource, "node-uid", labels.LabelRemoteNode)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{aPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	assert.False(t, IPIdentityCache.ipToIdentityCache["100.4.16.32/32"].ID.HasLocalScope())
}

// TestInjectExisting tests "upgrading" an existing identity to the apiserver.
// This is a common occurrence on startup - and this tests ensures we don't
// regress the known issue in GH-24502
func TestInjectExisting(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	// mimic the "restore cidr" logic from daemon.go
	// for every ip -> identity mapping in the bpf ipcache
	// - allocate that identity
	// - insert the cidr=>identity mapping back in to the go ipcache
	identities := make(map[netip.Prefix]*identity.Identity)
	prefix := netip.MustParsePrefix("172.19.0.5/32")
	oldID := identity.NumericIdentity(16777219)
	_, err := IPIdentityCache.AllocateCIDRs([]netip.Prefix{prefix}, []identity.NumericIdentity{oldID}, identities)
	assert.NoError(t, err)

	IPIdentityCache.UpsertGeneratedIdentities(identities, nil)

	// sanity check: ensure the cidr is correctly in the ipcache
	id, ok := IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, int32(16777219), int32(id.ID))

	// Simulate the first half of UpsertLabels -- insert the labels only in to the metadata cache
	// This is to "force" a race condition
	resource := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindEndpoint, "default", "kubernetes")
	IPIdentityCache.metadata.upsertLocked(prefix, source.KubeAPIServer, resource, labels.LabelKubeAPIServer)

	// Now, emulate policyAdd(), which calls AllocateCIDRs()
	_, err = IPIdentityCache.AllocateCIDRs([]netip.Prefix{prefix}, []identity.NumericIdentity{oldID}, nil)
	assert.NoError(t, err)

	// Now, trigger label injection
	// This will allocate a new ID for the same /32 since the labels have changed
	IPIdentityCache.UpsertLabels(prefix, labels.LabelKubeAPIServer, source.KubeAPIServer, resource)

	// Need to wait for the label injector to finish; easiest just to remove it
	IPIdentityCache.controllers.RemoveControllerAndWait(LabelInjectorName)

	// Ensure the source is now correctly understood in the ipcache
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.KubeAPIServer, id.Source)

}

func TestFilterMetadataByLabels(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	IPIdentityCache.metadata.upsertLocked(netip.MustParsePrefix("2.1.1.1/32"), source.Generated, "gen-uid", labels.LabelWorld)
	IPIdentityCache.metadata.upsertLocked(netip.MustParsePrefix("3.1.1.1/32"), source.Generated, "gen-uid-2", labels.LabelWorld)

	assert.Len(t, IPIdentityCache.metadata.filterByLabels(labels.LabelKubeAPIServer), 1)
	assert.Len(t, IPIdentityCache.metadata.filterByLabels(labels.LabelWorld), 2)
}

func TestRemoveLabelsFromIPs(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()
	ctx := context.Background()

	assert.Len(t, IPIdentityCache.metadata.m, 1)
	remaining, err := IPIdentityCache.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	IPIdentityCache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer, map[netip.Prefix]struct{}{},
		"kube-uid")
	assert.Len(t, IPIdentityCache.metadata.m, 1)
	assert.Equal(t, labels.LabelHost, IPIdentityCache.metadata.m[worldPrefix].ToLabels())

	// Simulate kube-apiserver policy + CIDR policy on same prefix. Validate
	// that removing the kube-apiserver policy will result in a new CIDR
	// identity for the CIDR policy.

	delete(IPIdentityCache.metadata.m, worldPrefix) // clean slate first
	// Entry with only kube-apiserver labels means kube-apiserver is outside of
	// the cluster, and thus will have a CIDR identity when InjectLabels() is
	// called.
	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.CustomResource, "kube-uid", labels.LabelKubeAPIServer)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	id := IPIdentityCache.IdentityAllocator.LookupIdentityByID(
		context.TODO(),
		identity.LocalIdentityFlag, // we assume first local ID
	)
	assert.NotNil(t, id)
	assert.Equal(t, 1, id.ReferenceCount)
	// Simulate adding CIDR policy.
	ids, err := IPIdentityCache.AllocateCIDRsForIPs([]net.IP{net.ParseIP("1.1.1.1").To4()}, nil)
	assert.Nil(t, err)
	assert.Len(t, ids, 1)
	assert.Equal(t, 2, id.ReferenceCount)
	IPIdentityCache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer, map[netip.Prefix]struct{}{},
		"kube-uid")
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.NotContains(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels(), labels.LabelKubeAPIServer)
	assert.Equal(t, 1, id.ReferenceCount) // CIDR policy is left
}

func setupTest(t *testing.T) (cleanup func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	allocator := testidentity.NewMockIdentityAllocator(nil)
	IPIdentityCache = NewIPCache(&Configuration{
		Context:           ctx,
		IdentityAllocator: allocator,
		PolicyHandler:     &mockUpdater{},
		DatapathHandler:   &mockTriggerer{},
	})
	IPIdentityCache.k8sSyncedChecker = &mockK8sSyncedChecker{}

	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.CustomResource, "kube-uid", labels.LabelKubeAPIServer)
	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.Local, "host-uid", labels.LabelHost)

	return func() {
		cancel()
		IPIdentityCache.Shutdown()
	}
}

type mockK8sSyncedChecker struct{}

func (m *mockK8sSyncedChecker) K8sCacheIsSynced() bool { return true }

type mockUpdater struct {
	added, removed cache.IdentityCache
}

func (m *mockUpdater) UpdateIdentities(added, removed cache.IdentityCache, _ *sync.WaitGroup) {
	m.added = added
	m.removed = removed
}

type mockTriggerer struct{}

func (m *mockTriggerer) UpdatePolicyMaps(ctx context.Context, wg *sync.WaitGroup) *sync.WaitGroup {
	return wg
}
