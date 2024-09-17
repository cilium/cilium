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
	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/ipcache/types/fake"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

var (
	worldPrefix      = netip.MustParsePrefix("1.1.1.1/32")
	inClusterPrefix  = netip.MustParsePrefix("10.0.0.4/32")
	inClusterPrefix2 = netip.MustParsePrefix("10.0.0.5/32")
	aPrefix          = netip.MustParsePrefix("100.4.16.32/32")
	allCIDRsPrefix   = netip.MustParsePrefix("0.0.0.0/0")
)

func TestInjectLabels(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	assert.Len(t, IPIdentityCache.metadata.m, 1)
	remaining, err := IPIdentityCache.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.Len(t, remaining, 0)
	assert.NoError(t, err)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	// Insert kube-apiserver IP from outside of the cluster. This should create
	// a CIDR ID for this IP.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.True(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())

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

	// Clean up.
	IPIdentityCache.metadata.remove(inClusterPrefix, "node-uid", overrideIdentity(false), labels.LabelRemoteNode)
	IPIdentityCache.metadata.remove(inClusterPrefix, "kube-uid", overrideIdentity(false), labels.LabelKubeAPIServer)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.metadata.m, 1)

	// Assert that an upsert for reserved:health label results in only the
	// reserved health ID.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "node-uid", labels.LabelHealth)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityHealth, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID)

	// Assert that an upsert for reserved:ingress label results in only the
	// reserved ingress ID.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.Local, "node-uid", labels.LabelIngress)
	assert.Len(t, IPIdentityCache.metadata.m, 3)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix2})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityIngress, IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID)
	// Clean up.
	IPIdentityCache.metadata.remove(inClusterPrefix2, "node-uid", overrideIdentity(false), labels.LabelIngress)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix2})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.metadata.m, 2)

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

	// Assert that an upsert for reserved:world label results in only the
	// reserved world ID.
	IPIdentityCache.metadata.upsertLocked(allCIDRsPrefix, source.Local, "daemon-uid", labels.LabelWorld)
	assert.Len(t, IPIdentityCache.metadata.m, 4)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{allCIDRsPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 4)
	assert.False(t, IPIdentityCache.ipToIdentityCache["0.0.0.0/0"].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityWorld, IPIdentityCache.ipToIdentityCache["0.0.0.0/0"].ID)
}

// Test that when multiple IPs have the `resolved:host` label, we correctly
// aggregate all labels *and* update the selector cache correctly.
// This reproduces GH-28259.
func TestUpdateLocalNode(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	bothLabels := labels.Labels{}
	bothLabels.MergeLabels(labels.LabelHost)
	bothLabels.MergeLabels(labels.LabelKubeAPIServer)

	selectorCacheHas := func(lbls labels.Labels) {
		t.Helper()
		id := PolicyHandler.identities[identity.ReservedIdentityHost]
		assert.NotNil(t, id)
		assert.Equal(t, lbls.LabelArray(), id)
	}

	injectLabels := func(ip netip.Prefix) {
		t.Helper()
		remaining, err := IPIdentityCache.InjectLabels(ctx, []netip.Prefix{ip})
		assert.NoError(t, err)
		assert.Len(t, remaining, 0)
	}

	idIs := func(ip netip.Prefix, id identity.NumericIdentity) {
		t.Helper()
		assert.Equal(t, IPIdentityCache.ipToIdentityCache[ip.String()].ID, id)
	}

	// Mark .4 as local host
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "node-uid", labels.LabelHost)
	injectLabels(inClusterPrefix)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	selectorCacheHas(labels.LabelHost)

	// Mark .4 as kube-apiserver
	// Note that in the actual code, we use `source.KubeAPIServer`. However,
	// we use the same source in test case to try and ferret out more bugs.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "kube-uid", labels.LabelKubeAPIServer)
	injectLabels(inClusterPrefix)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	selectorCacheHas(bothLabels)

	// Mark .5 as local host
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.Local, "node-uid", labels.LabelHost)
	injectLabels(inClusterPrefix2)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	selectorCacheHas(bothLabels)

	// remove kube-apiserver from .4
	IPIdentityCache.metadata.remove(inClusterPrefix, "kube-uid", labels.LabelKubeAPIServer)
	injectLabels(inClusterPrefix)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	selectorCacheHas(labels.LabelHost)

	// add kube-apiserver back to .4
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "kube-uid", labels.LabelKubeAPIServer)
	injectLabels(inClusterPrefix)
	idIs(inClusterPrefix, identity.ReservedIdentityHost)
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	selectorCacheHas(bothLabels)

	// remove host from .4
	IPIdentityCache.metadata.remove(inClusterPrefix, "node-uid", labels.LabelHost)
	injectLabels(inClusterPrefix)

	// Verify that .4 now has just kube-apiserver and CIDRs
	idIs(inClusterPrefix, identity.LocalIdentityFlag) // the first CIDR identity
	id := PolicyHandler.identities[identity.LocalIdentityFlag]
	assert.True(t, id.Has("reserved.kube-apiserver"))
	assert.True(t, id.Has("cidr."+inClusterPrefix.String()))

	// verify that id 1 is now just reserved:host
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	selectorCacheHas(labels.LabelHost)
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
	resource := types.NewResourceID(
		types.ResourceKindEndpoint, "default", "kubernetes")
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

// TestInjectWithLegacyAPIOverlap tests that a previously allocated identity
// will continue to be used in the ipcache even if other users of newer APIs
// also use the API, and that reference counting is properly balanced for this
// pattern.This is a common occurrence on startup - and this tests ensures we
// don't regress the known issue in GH-24502
//
// This differs from TestInjectExisting() by reusing the same identity, and by
// not associating any new labels with the prefix.
func TestInjectWithLegacyAPIOverlap(t *testing.T) {
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
	identityReferences := 1

	IPIdentityCache.UpsertGeneratedIdentities(identities, nil)

	// sanity check: ensure the cidr is correctly in the ipcache
	id, ok := IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, int32(16777219), int32(id.ID))

	// Simulate the first half of UpsertLabels -- insert the labels only in to the metadata cache
	// This is to "force" a race condition
	resource := types.NewResourceID(
		types.ResourceKindCNP, "default", "policy")
	labels := cidr.GetCIDRLabels(prefix)
	IPIdentityCache.metadata.upsertLocked(prefix, source.CustomResource, resource, labels)

	// Now, emulate policyAdd(), which calls AllocateCIDRs()
	_, err = IPIdentityCache.AllocateCIDRs([]netip.Prefix{prefix}, []identity.NumericIdentity{oldID}, nil)
	assert.NoError(t, err)
	identityReferences++

	// Now, trigger label injection
	// This will allocate a new ID for the same /32 since the labels have changed
	// It should only allocate once, even if we run it multiple times.
	identityReferences++
	for i := 0; i < 2; i++ {
		IPIdentityCache.UpsertLabels(prefix, labels, source.CustomResource, resource)
		// Need to wait for the label injector to finish; easiest just to remove it
		IPIdentityCache.controllers.RemoveControllerAndWait(LabelInjectorName)
	}

	// Ensure the source is now correctly understood in the ipcache
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.CustomResource, id.Source)

	// Release the identity references via the legacy API. As long as the
	// external subsystems are balancing their references against the
	// identities, then the remainder of the test will assert that the
	// ipcache internals will properly reference-count the identities
	// for users of the newer APIs where ipcache itself is responsible for
	// reference counting.
	for i := identityReferences; i > 1; i-- {
		IPIdentityCache.releaseCIDRIdentities(context.Background(), []netip.Prefix{prefix})
		identityReferences--
	}

	// sanity check: ensure the cidr is correctly in the ipcache
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, oldID.Uint32(), id.ID.Uint32())

	// Check that the corresponding identity in the identity allocator
	// is still allocated, which implies that it's reference counted
	// correctly compared to the identityReferences variable in this test.
	realID := IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.True(t, realID != nil)
	assert.Equal(t, id.ID.Uint32(), uint32(realID.ID))

	// Remove the identity allocation via newer APIs
	IPIdentityCache.RemoveLabels(prefix, labels, resource)
	IPIdentityCache.controllers.RemoveControllerAndWait(LabelInjectorName)
	identityReferences--
	assert.Equal(t, identityReferences, 0)

	// Assert that ipcache has released its final reference to the identity
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.True(t, realID == nil)

	_, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.False(t, ok)
}

// TestInjectWithLegacyAPIToUnmanaged tests that entries inserted by the
// legacy API are correctly handled when metadata is added and removed via
// the new API. It emulates the following sequence:
//  1. AllocateCIDRs(p)  -- owned by legacy API
//  2. UpsertPrefixes(p) -- shared ownership
//  3. RemovePrefixes(p) -- owned by legacy API
//  4. UpsertPrefixes(p) -- shared ownership again
//  5. RemovePrefixes(p) -- owned by legacy API
//  6. releaseCIDRs(p)   -- legacy entry needs to be removed
func TestInjectWithLegacyAPIToUnmanaged(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	// mimic the "restore cidr" logic from daemon.go
	// for every ip -> identity mapping in the bpf ipcache
	// - allocate that identity
	// - insert the cidr=>identity mapping back in to the go ipcache
	identities := make(map[netip.Prefix]*identity.Identity)
	prefix := netip.MustParsePrefix("172.19.0.5/32")
	prefixID := identity.NumericIdentity(16777219)
	_, err := IPIdentityCache.AllocateCIDRs([]netip.Prefix{prefix}, []identity.NumericIdentity{prefixID}, identities)
	assert.NoError(t, err)

	IPIdentityCache.UpsertGeneratedIdentities(identities, nil)

	// sanity check: ensure the cidr is correctly in the ipcache
	id, ok := IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, int32(prefixID), int32(id.ID))
	assert.Equal(t, source.Generated, id.Source)

	// Check refcount
	realID := IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 1, realID.ReferenceCount)

	// Simulate UpsertPrefixes
	resource := types.NewResourceID(
		types.ResourceKindCNP, "default", "policy")
	labels := cidr.GetCIDRLabels(prefix)
	IPIdentityCache.metadata.upsertLocked(prefix, source.CustomResource, resource, labels)
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{prefix})
	assert.NoError(t, err)

	// Ensure the source is now correctly understood in the ipcache
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.CustomResource, id.Source)

	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 2, realID.ReferenceCount)

	// Simulate RemovePrefixes
	IPIdentityCache.metadata.remove(prefix, resource, labels)
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{prefix})
	assert.NoError(t, err)

	// Ensure the entry has been downgraded to the legacy source
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.Generated, id.Source)

	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 1, realID.ReferenceCount)

	// UpsertPrefixes again. This asserts that even thought the entry was touched by
	// metadata at some point, we still properly upgrade it again
	IPIdentityCache.metadata.upsertLocked(prefix, source.CustomResource, resource, labels)
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{prefix})
	assert.NoError(t, err)

	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.CustomResource, id.Source)
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 2, realID.ReferenceCount)

	// RemovePrefixes
	IPIdentityCache.metadata.remove(prefix, resource, labels)
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{prefix})
	assert.NoError(t, err)

	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.Generated, id.Source)
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 1, realID.ReferenceCount)

	// Assert that releaseCIDRs works
	IPIdentityCache.releaseCIDRIdentities(context.Background(), []netip.Prefix{prefix})

	// Assert that ipcache has released its final reference to the identity
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.True(t, realID == nil)
	_, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.False(t, ok)
}

// TestInjectWithMetadataAPIBeforeLegacyUpsert tests that entries inserted by the
// metadata API are correctly handled when a legacy caller also attempts to
// upsert them via AllocateCIDRs/UpsertGeneratedIdentities
//  1. UpsertPrefixes(p) -- owned by metadata API
//  2. AllocateCIDRs(p)  -- co-owned by both APIs
//  3. RemovePrefixes(p) -- owned by legacy API
//  4. UpsertPrefixes(p) -- shared ownership again
//  5. releaseCIDRs(p)   -- shared ownership (but only managed by metadata)
//  6. RemovePrefixes(p) -- entry is removed
func TestInjectWithLegacyAPIForExistingIdentities(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	// Simulate UpsertPrefixes
	prefix := netip.MustParsePrefix("172.19.0.5/32")
	resource := types.NewResourceID(
		types.ResourceKindCNP, "default", "policy")
	labels := cidr.GetCIDRLabels(prefix)
	IPIdentityCache.metadata.upsertLocked(prefix, source.CustomResource, resource, labels)
	_, err := IPIdentityCache.InjectLabels(ctx, []netip.Prefix{prefix})
	assert.NoError(t, err)

	// Ensure the entry is in IPCache with refcount=1
	id, ok := IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.CustomResource, id.Source)
	realID := IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 1, realID.ReferenceCount)

	// Simulate AllocateCIDRs/UpsertGeneratedIdentities (e.g. due to FQDN lookups)
	prefix2 := netip.MustParsePrefix("172.19.0.6/32")
	identities := make(map[netip.Prefix]*identity.Identity)
	usedIdentities, err := IPIdentityCache.AllocateCIDRs([]netip.Prefix{prefix, prefix2}, nil, identities)
	assert.NoError(t, err)
	assert.Len(t, usedIdentities, 2)
	assert.Len(t, identities, 1)
	IPIdentityCache.UpsertGeneratedIdentities(identities, usedIdentities)

	// Ensure the entry is in IPCache with still the correct source and refcount=2
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.CustomResource, id.Source)
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 2, realID.ReferenceCount)

	// Ensure the other entry is also IPCache with the legacy source
	id2, ok := IPIdentityCache.LookupByIP(prefix2.String())
	assert.True(t, ok)
	assert.Equal(t, source.Generated, id2.Source)
	realID2 := IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id2.ID)
	assert.Equal(t, 1, realID2.ReferenceCount)

	// Simulate RemovePrefixes
	IPIdentityCache.metadata.remove(prefix, resource, labels)
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{prefix})
	assert.NoError(t, err)

	// Ensure the entry has been downgraded to the legacy source
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.Generated, id.Source)
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 1, realID.ReferenceCount)

	// Shared ownership again
	IPIdentityCache.metadata.upsertLocked(prefix, source.CustomResource, resource, labels)
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{prefix})
	assert.NoError(t, err)

	// Ensure the entry source and refcount are bumped again
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.CustomResource, id.Source)
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 2, realID.ReferenceCount)

	// Assert that releaseCIDRs decreases refcount
	IPIdentityCache.releaseCIDRIdentities(context.Background(), []netip.Prefix{prefix, prefix2})

	// prefix should have only the metadata owner left
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.CustomResource, id.Source)
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Equal(t, 1, realID.ReferenceCount)

	// prefix2 should be removed
	realID2 = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id2.ID)
	assert.Nil(t, realID2)
	_, ok = IPIdentityCache.LookupByIP(prefix2.String())
	assert.False(t, ok)

	// Simulate RemovePrefixes
	IPIdentityCache.metadata.remove(prefix, resource, labels)
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{prefix})
	assert.NoError(t, err)

	// Assert that IPCache released its final reference to the identity
	realID = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.Background(), id.ID)
	assert.Nil(t, realID)
	_, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.False(t, ok)
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

	// Attempting to remove a label for a ResourceID which does not exist
	// should not remove anything.
	IPIdentityCache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer, map[netip.Prefix]struct{}{},
		"foo")
	assert.Len(t, IPIdentityCache.metadata.m, 1)
	assert.Contains(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels(), labels.IDNameKubeAPIServer)

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
	assert.NotContains(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels(), labels.IDNameKubeAPIServer)
	assert.Equal(t, 1, id.ReferenceCount) // CIDR policy is left
}

func TestOverrideIdentity(t *testing.T) {
	allocator := testidentity.NewMockIdentityAllocator(nil)

	// pre-allocate override identities
	fooLabels := labels.NewLabelsFromSortedList("k8s:name=foo")
	fooID, isNew, err := allocator.AllocateIdentity(context.TODO(), fooLabels, false, identity.InvalidIdentity)
	assert.Equal(t, fooID.ReferenceCount, 1)
	assert.NoError(t, err)
	assert.True(t, isNew)

	barLabels := labels.NewLabelsFromSortedList("k8s:name=bar")
	barID, isNew, err := allocator.AllocateIdentity(context.TODO(), barLabels, false, identity.InvalidIdentity)
	assert.Equal(t, fooID.ReferenceCount, 1)
	assert.NoError(t, err)
	assert.True(t, isNew)

	ipc := NewIPCache(&Configuration{
		IdentityAllocator: allocator,
		PolicyHandler:     newMockUpdater(),
		DatapathHandler:   &mockTriggerer{},
	})
	ctx := context.Background()

	// Create CIDR identity from labels
	ipc.metadata.upsertLocked(worldPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	remaining, err := ipc.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	id, ok := ipc.LookupByPrefix(worldPrefix.String())
	assert.True(t, ok)
	assert.True(t, id.ID.HasLocalScope())
	assert.False(t, id.ID.IsReservedIdentity())

	// Force an identity override
	ipc.metadata.upsertLocked(worldPrefix, source.CustomResource, "cep-uid", overrideIdentity(true), fooLabels)
	remaining, err = ipc.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	id, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.True(t, ok)
	assert.Equal(t, fooID.ReferenceCount, 2)
	assert.Equal(t, id.ID, fooID.ID)

	// Remove identity override from prefix, should assign a CIDR identity again
	ipc.metadata.remove(worldPrefix, "cep-uid", overrideIdentity(true), fooLabels)
	remaining, err = ipc.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	id, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.True(t, ok)
	assert.True(t, id.ID.HasLocalScope())
	assert.False(t, id.ID.IsReservedIdentity())
	assert.Equal(t, fooID.ReferenceCount, 1)

	// Remove remaining labels from prefix, this should remove the entry
	ipc.metadata.remove(worldPrefix, "kube-uid", labels.LabelKubeAPIServer)
	remaining, err = ipc.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	_, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.False(t, ok)

	// Create a new entry again via override
	ipc.metadata.upsertLocked(worldPrefix, source.CustomResource, "cep-uid", overrideIdentity(true), barLabels)
	remaining, err = ipc.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	// Add labels, those will be ignored due to override
	ipc.metadata.upsertLocked(worldPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	remaining, err = ipc.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	id, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.True(t, ok)
	assert.Equal(t, id.ID, barID.ID)
	assert.Equal(t, barID.ReferenceCount, 2)

	// Remove all metadata at once, this should remove the whole entry
	ipc.metadata.remove(worldPrefix, "kube-uid", labels.LabelKubeAPIServer)
	ipc.metadata.remove(worldPrefix, "cep-uid", overrideIdentity(true), barLabels)
	remaining, err = ipc.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	_, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.Equal(t, barID.ReferenceCount, 1)
	assert.False(t, ok)
}

func TestUpsertMetadataTunnelPeerAndEncryptKey(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid",
		types.TunnelPeer{Addr: netip.MustParseAddr("192.168.1.100")},
		types.EncryptKey(7))
	remaining, err := IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	ip, key := IPIdentityCache.getHostIPCache(inClusterPrefix.String())
	assert.Equal(t, "192.168.1.100", ip.String())
	assert.Equal(t, uint8(7), key)

	// Assert that an entry with a weaker source (and from a different
	// resource) should fail, i.e. at least does not overwrite the existing
	// (stronger) ipcache entry.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Generated, "generated-uid",
		types.TunnelPeer{Addr: netip.MustParseAddr("192.168.1.101")},
		types.EncryptKey(6))
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	ip, key = IPIdentityCache.getHostIPCache(inClusterPrefix.String())
	assert.Equal(t, "192.168.1.100", ip.String())
	assert.Equal(t, uint8(7), key)

	// Remove the entry with the encryptKey=7 and encryptKey=6.
	IPIdentityCache.metadata.remove(inClusterPrefix, "node-uid", types.EncryptKey(7))
	IPIdentityCache.metadata.remove(inClusterPrefix, "generated-uid", types.EncryptKey(6))
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	// Assert that there should only be the entry with the tunnelPeer set.
	ip, key = IPIdentityCache.getHostIPCache(inClusterPrefix.String())
	assert.Equal(t, "192.168.1.100", ip.String())
	assert.Equal(t, uint8(0), key)

	// The following tests whether an entry with a high priority source
	// (KubeAPIServer) allows lower priority sources to set the TunnelPeer and
	// EncryptKey.
	//
	// Start with a KubeAPIServer entry with just labels.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.KubeAPIServer, "kube-uid",
		labels.LabelKubeAPIServer,
	)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	// Add TunnelPeer and EncryptKey from the CustomResource source.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid",
		labels.LabelRemoteNode,
		types.TunnelPeer{Addr: netip.MustParseAddr("192.168.1.101")},
		types.EncryptKey(6),
	)
	_, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	ip, key = IPIdentityCache.getHostIPCache(inClusterPrefix.String())
	assert.Equal(t, "192.168.1.101", ip.String())
	assert.Equal(t, uint8(6), key)
}

func setupTest(t *testing.T) (cleanup func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	allocator := testidentity.NewMockIdentityAllocator(nil)
	PolicyHandler = newMockUpdater()
	IPIdentityCache = NewIPCache(&Configuration{
		Context:           ctx,
		IdentityAllocator: allocator,
		PolicyHandler:     PolicyHandler,
		DatapathHandler:   &mockTriggerer{},
		NodeIDHandler:     &fake.FakeNodeIDHandler{},
	})

	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.CustomResource, "kube-uid", labels.LabelKubeAPIServer)
	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.Local, "host-uid", labels.LabelHost)

	return func() {
		cancel()
		IPIdentityCache.Shutdown()
	}
}

func newMockUpdater() *mockUpdater {
	return &mockUpdater{
		identities: make(map[identity.NumericIdentity]labels.LabelArray),
	}
}

type mockUpdater struct {
	identities map[identity.NumericIdentity]labels.LabelArray
}

func (m *mockUpdater) UpdateIdentities(added, deleted cache.IdentityCache, _ *sync.WaitGroup) {
	for nid, lbls := range added {
		m.identities[nid] = lbls
	}

	for nid := range deleted {
		delete(m.identities, nid)
	}
}

type mockTriggerer struct{}

func (m *mockTriggerer) UpdatePolicyMaps(ctx context.Context, wg *sync.WaitGroup) *sync.WaitGroup {
	return wg
}
