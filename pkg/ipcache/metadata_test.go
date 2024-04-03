// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	ipv4All = "0.0.0.0/0"
	ipv6All = "::/0"
)

var (
	worldPrefix        = netip.MustParsePrefix("1.1.1.1/32")
	inClusterPrefix    = netip.MustParsePrefix("10.0.0.4/32")
	inClusterPrefix2   = netip.MustParsePrefix("10.0.0.5/32")
	aPrefix            = netip.MustParsePrefix("100.4.16.32/32")
	allIPv4CIDRsPrefix = netip.MustParsePrefix(ipv4All)
	allIPv6CIDRsPrefix = netip.MustParsePrefix(ipv6All)
)

func TestInjectLabels(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	// disable policy-cidr-selects-nodes, which affects identity management
	oldVal := option.Config.PolicyCIDRMatchMode
	defer func() {
		option.Config.PolicyCIDRMatchMode = oldVal
	}()

	option.Config.PolicyCIDRMatchMode = []string{}

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
	// IP now (unless we are enabling policy-cidr-match-mode=remote-node).
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid", labels.LabelRemoteNode)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityKubeAPIServer, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID)

	// Insert another node, see that it gets the RemoteNode ID but not kube-apiserver
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.CustomResource, "node-uid", labels.LabelRemoteNode)
	assert.Len(t, IPIdentityCache.metadata.m, 3)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix2})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	assert.Equal(t, identity.ReservedIdentityRemoteNode, IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID)

	// Enable policy-cidr-selects-nodes, ensure that node now has a separate identity (in the node id scope)
	option.Config.PolicyCIDRMatchMode = []string{"nodes"}

	// Insert CIDR labels for the remote nodes (this is done by the node manager, but we need to test that it goes through)
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid-cidr", labels.GetCIDRLabels(inClusterPrefix))
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.CustomResource, "node-uid-cidr", labels.GetCIDRLabels(inClusterPrefix2))

	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix, inClusterPrefix2})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	nid1 := IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID
	nid2 := IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID
	assert.Equal(t, identity.IdentityScopeRemoteNode, nid1.Scope())
	assert.Equal(t, identity.IdentityScopeRemoteNode, nid2.Scope())

	// Ensure that all expected labels have been allocated
	// -- prefix1 should have kube-apiserver, remote-node, and cidr
	// -- prefix2 should have remote-node and cidr
	id1 := IPIdentityCache.IdentityAllocator.LookupIdentityByID(ctx, nid1)
	assert.NotNil(t, id1)
	assert.True(t, id1.Labels.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]))
	assert.True(t, id1.Labels.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]))
	assert.True(t, id1.Labels.Has(labels.ParseLabel("cidr:10.0.0.4/32")))
	assert.False(t, id1.Labels.Has(labels.ParseLabel("cidr:10.0.0.5/32")))

	id2 := IPIdentityCache.IdentityAllocator.LookupIdentityByID(ctx, nid2)
	assert.NotNil(t, id2)
	assert.True(t, id2.Labels.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]))
	assert.False(t, id2.Labels.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]))
	assert.False(t, id2.Labels.Has(labels.ParseLabel("cidr:10.0.0.4/32")))
	assert.True(t, id2.Labels.Has(labels.ParseLabel("cidr:10.0.0.5/32")))

	// Remove remote-node label, ensure transition to local cidr identity space
	IPIdentityCache.metadata.remove(inClusterPrefix, "node-uid", overrideIdentity(false), labels.LabelRemoteNode)
	IPIdentityCache.metadata.remove(inClusterPrefix2, "node-uid", overrideIdentity(false), labels.LabelRemoteNode)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix, inClusterPrefix2})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	nid1 = IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID
	nid2 = IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID
	assert.Equal(t, identity.IdentityScopeLocal, nid1.Scope())
	assert.Equal(t, identity.IdentityScopeLocal, nid2.Scope())

	id1 = IPIdentityCache.IdentityAllocator.LookupIdentityByID(ctx, nid1)
	assert.NotNil(t, id1)
	assert.False(t, id1.Labels.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]))
	assert.True(t, id1.Labels.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]))
	assert.True(t, id1.Labels.Has(labels.ParseLabel("cidr:10.0.0.4/32")))
	assert.False(t, id1.Labels.Has(labels.ParseLabel("cidr:10.0.0.5/32")))

	id2 = IPIdentityCache.IdentityAllocator.LookupIdentityByID(ctx, nid2)
	assert.NotNil(t, id2)
	assert.False(t, id2.Labels.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]))
	assert.False(t, id2.Labels.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]))
	assert.False(t, id2.Labels.Has(labels.ParseLabel("cidr:10.0.0.4/32")))
	assert.True(t, id2.Labels.Has(labels.ParseLabel("cidr:10.0.0.5/32")))

	// Clean up.
	IPIdentityCache.metadata.remove(inClusterPrefix, "node-uid-cidr", overrideIdentity(false), labels.Labels{})
	IPIdentityCache.metadata.remove(inClusterPrefix2, "node-uid-cidr", overrideIdentity(false), labels.Labels{})
	IPIdentityCache.metadata.remove(inClusterPrefix, "kube-uid", overrideIdentity(false), labels.LabelKubeAPIServer)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{inClusterPrefix, inClusterPrefix2})
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

	// Assert that, in dual stack mode, an upsert for reserved:world-ipv4 label results in only the
	// reserved world-ipv4 ID.
	IPIdentityCache.metadata.upsertLocked(allIPv4CIDRsPrefix, source.Local, "daemon-uid", labels.LabelWorldIPv4)
	assert.Len(t, IPIdentityCache.metadata.m, 4)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{allIPv4CIDRsPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 4)
	assert.False(t, IPIdentityCache.ipToIdentityCache[ipv4All].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityWorldIPv4, IPIdentityCache.ipToIdentityCache[ipv4All].ID)

	// Assert that, in dual stack mode, an upsert for reserved:world-ipv6 label results in only the
	// reserved world-ipv6 ID.
	IPIdentityCache.metadata.upsertLocked(allIPv6CIDRsPrefix, source.Local, "daemon-uid", labels.LabelWorldIPv6)
	assert.Len(t, IPIdentityCache.metadata.m, 5)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{allIPv6CIDRsPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 5)
	assert.False(t, IPIdentityCache.ipToIdentityCache[ipv6All].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityWorldIPv6, IPIdentityCache.ipToIdentityCache[ipv6All].ID)

	// Assert that, in ipv4-only mode, an upsert for reserved:world label results in only the
	// reserved world ID.
	option.Config.EnableIPv6 = false
	IPIdentityCache.metadata.upsertLocked(allIPv4CIDRsPrefix, source.Local, "daemon-uid", labels.LabelWorld)
	assert.Len(t, IPIdentityCache.metadata.m, 5)
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{allIPv4CIDRsPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 5)
	assert.False(t, IPIdentityCache.ipToIdentityCache[ipv4All].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityWorld, IPIdentityCache.ipToIdentityCache[ipv4All].ID)
	option.Config.EnableIPv6 = true
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
	idIs(inClusterPrefix, identity.IdentityScopeLocal) // the first CIDR identity
	id := PolicyHandler.identities[identity.IdentityScopeLocal]
	assert.True(t, id.Has("reserved.kube-apiserver"))
	assert.True(t, id.Has("cidr."+inClusterPrefix.String()))

	// verify that id 1 is now just reserved:host
	idIs(inClusterPrefix2, identity.ReservedIdentityHost)
	selectorCacheHas(labels.LabelHost)
}

// TestInjectExisting tests "upgrading" an existing identity to the apiserver.
// This is possible if a CIDR policy references a given IP, which is then
// upgraded to the apiserver.
//
// This was intended to ensure we don't regress on GH-24502, but that is moot
// now that identity restoration happens using the asynch apis.
func TestInjectExisting(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	// mimic fqdn policy:
	// - NameManager.updateDNSIPs calls UpsertPrefixes() when then inserts them
	//   via TriggerLabelInjection.
	fqdnResourceID := types.NewResourceID(types.ResourceKindDaemon, "", "fqdn-name-manager")
	prefix := netip.MustParsePrefix("172.19.0.5/32")
	IPIdentityCache.metadata.upsertLocked(prefix, source.Generated, fqdnResourceID)
	remaining, err := IPIdentityCache.InjectLabels(context.Background(), []netip.Prefix{prefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	// sanity check: ensure the cidr is correctly in the ipcache
	wantID := identity.IdentityScopeLocal
	id, ok := IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, wantID, id.ID)

	// Simulate the first half of UpsertLabels -- insert the labels only in to the metadata cache
	// This is to "force" a race condition
	resource := types.NewResourceID(
		types.ResourceKindEndpoint, "default", "kubernetes")
	IPIdentityCache.metadata.upsertLocked(prefix, source.KubeAPIServer, resource, labels.LabelKubeAPIServer)

	// Now, emulate a ToServices policy, which calls UpsertPrefixes
	IPIdentityCache.metadata.upsertLocked(prefix, source.CustomResource, "policy-uid", labels.GetCIDRLabels(prefix))

	// Now, the second half of UpsertLabels -- identity injection
	remaining, err = IPIdentityCache.InjectLabels(context.Background(), []netip.Prefix{prefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)

	// Ensure the source is now correctly understood in the ipcache
	id, ok = IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, source.KubeAPIServer, id.Source)

	// Ensure the SelectorCache has the correct labels
	selectorID := PolicyHandler.identities[id.ID]
	assert.NotNil(t, selectorID)
	assert.True(t, selectorID.Contains(labels.LabelKubeAPIServer.LabelArray()))
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
		identity.IdentityScopeLocal, // we assume first local ID
	)
	assert.NotNil(t, id)
	assert.Equal(t, 1, id.ReferenceCount)

	// Simulate adding CIDR policy by simulating UpsertPrefixes
	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.CustomResource, "policy-uid", labels.GetCIDRLabels(worldPrefix))
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.Nil(t, err)
	assert.Zero(t, remaining)
	assert.Contains(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels(), labels.IDNameKubeAPIServer)
	nid, exists := IPIdentityCache.LookupByPrefix(worldPrefix.String())
	assert.True(t, exists)
	id = IPIdentityCache.IdentityAllocator.LookupIdentityByID(
		context.TODO(),
		nid.ID,
	)
	assert.Equal(t, 1, id.ReferenceCount) // InjectLabels calls allocate and release on ID

	// Remove kube-apiserver label
	IPIdentityCache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer, map[netip.Prefix]struct{}{},
		"kube-uid")
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.NotContains(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels(), labels.IDNameKubeAPIServer)
	nid, exists = IPIdentityCache.LookupByPrefix(worldPrefix.String())
	assert.True(t, exists)
	id = IPIdentityCache.IdentityAllocator.LookupIdentityByID(
		context.TODO(),
		nid.ID,
	)
	assert.Equal(t, 1, id.ReferenceCount) // CIDR policy is left

	// Simulate removing CIDR policy.
	IPIdentityCache.RemoveLabels(worldPrefix, labels.Labels{}, "policy-uid")
	remaining, err = IPIdentityCache.InjectLabels(ctx, []netip.Prefix{worldPrefix})
	assert.NoError(t, err)
	assert.Len(t, remaining, 0)
	assert.Empty(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels())
	nid, exists = IPIdentityCache.LookupByPrefix(worldPrefix.String())
	assert.False(t, exists)
	id = IPIdentityCache.IdentityAllocator.LookupIdentityByID(
		context.TODO(),
		id.ID, // check old ID is deallocated
	)
	assert.Nil(t, id)
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

// TestRequestIdentity checks that the identity restoration mechanism works as expected:
// -- requested numeric identities are utilized
// -- if two prefixes somehow collide, everything still works
func TestRequestIdentity(t *testing.T) {
	cancel := setupTest(t)
	cancel()

	injectLabels := func(prefixes ...netip.Prefix) {
		t.Helper()
		remaining, err := IPIdentityCache.InjectLabels(context.Background(), prefixes)
		assert.NoError(t, err)
		assert.Len(t, remaining, 0)
	}

	hasIdentity := func(prefix netip.Prefix, nid identity.NumericIdentity) {
		t.Helper()
		id, _ := IPIdentityCache.LookupByPrefix(prefix.String())
		assert.EqualValues(t, nid, id.ID)
	}

	// Add 2 prefixes in to the ipcache, one requesting the first local identity
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Restored, "daemon-uid", types.RequestedIdentity(identity.IdentityScopeLocal))
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.Restored, "daemon-uid", labels.Labels{})

	// Withhold the first local-scoped identity in the allocator
	IPIdentityCache.IdentityAllocator.WithholdLocalIdentities([]identity.NumericIdentity{16777216})

	// Upsert the second prefix first, ensuring it does not get the withheld identituy
	injectLabels(inClusterPrefix2)
	injectLabels(inClusterPrefix)

	hasIdentity(inClusterPrefix, identity.IdentityScopeLocal)
	hasIdentity(inClusterPrefix2, identity.IdentityScopeLocal+1)

	// Attach the restored nid to another prefix, ensure it is ignored
	IPIdentityCache.metadata.upsertLocked(aPrefix, source.Restored, "daemon-uid", types.RequestedIdentity(identity.IdentityScopeLocal))
	injectLabels(aPrefix)
	hasIdentity(aPrefix, identity.IdentityScopeLocal+2)
}

func TestMetadataRevision(t *testing.T) {
	m := newMetadata()

	p1 := netip.MustParsePrefix("1.1.1.1/32")
	p2 := netip.MustParsePrefix("1::1/128")

	rev := m.enqueuePrefixUpdates(p1)
	assert.Equal(t, uint64(1), rev)

	rev = m.enqueuePrefixUpdates(p2)
	assert.Equal(t, uint64(1), rev)

	_, rev = m.dequeuePrefixUpdates()
	assert.Equal(t, uint64(1), rev)
	assert.Equal(t, uint64(0), m.injectedRevision)

	rev = m.enqueuePrefixUpdates(p1)
	assert.Equal(t, uint64(2), rev)
	assert.Equal(t, uint64(0), m.injectedRevision)

	m.setInjectedRevision(1)
	rev = m.enqueuePrefixUpdates(p2)
	assert.Equal(t, uint64(2), rev)
	assert.Equal(t, uint64(1), m.injectedRevision)
}

func TestMetadataWaitForRevision(t *testing.T) {
	m := newMetadata()

	p1 := netip.MustParsePrefix("1.1.1.1/32")
	wantRev := m.enqueuePrefixUpdates(p1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		m.waitForRevision(wantRev)
		wg.Done()
	}()

	m.setInjectedRevision(wantRev)
	wg.Wait()
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
	})

	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
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
