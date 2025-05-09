// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
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
	worldPrefix        = cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("1.1.1.1/32"))
	inClusterPrefix    = cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.4/32"))
	inClusterPrefix2   = cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.5/32"))
	aPrefix            = cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("100.4.16.32/32"))
	allIPv4CIDRsPrefix = cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix(ipv4All))
	allIPv6CIDRsPrefix = cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix(ipv6All))
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
	remaining, hostChanged, err := IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.Empty(t, remaining)
	assert.NoError(t, err)
	assert.True(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	// Insert kube-apiserver IP from outside of the cluster. This should create
	// a CIDR ID for this IP.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.True(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())

	// Upsert node labels to the kube-apiserver to validate that the CIDR ID is
	// deallocated and the kube-apiserver reserved ID is associated with this
	// IP now (unless we are enabling policy-cidr-match-mode=remote-node).
	prefixes := IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid", labels.LabelRemoteNode)
	assert.Len(t, prefixes, 1)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityKubeAPIServer, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID)

	// Insert the same data, see that it does not need to be updated
	prefixes = IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid", labels.LabelRemoteNode)
	assert.Empty(t, prefixes)

	// Insert another node, see that it gets the RemoteNode ID but not kube-apiserver
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.CustomResource, "node-uid", labels.LabelRemoteNode)
	assert.Len(t, IPIdentityCache.metadata.m, 3)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix2})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	assert.Equal(t, identity.ReservedIdentityRemoteNode, IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID)

	// Enable policy-cidr-selects-nodes, ensure that node now has a separate identity (in the node id scope)
	option.Config.PolicyCIDRMatchMode = []string{"nodes"}

	// Insert CIDR labels for the remote nodes (this is done by the node manager, but we need to test that it goes through)
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid-cidr", labels.GetCIDRLabels(inClusterPrefix.AsPrefix()))
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.CustomResource, "node-uid-cidr", labels.GetCIDRLabels(inClusterPrefix2.AsPrefix()))

	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix, inClusterPrefix2})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
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
	assert.True(t, id1.Labels.HasRemoteNodeLabel())
	assert.True(t, id1.Labels.HasKubeAPIServerLabel())
	assert.True(t, id1.Labels.Has(labels.ParseLabel("cidr:10.0.0.4/32")))
	assert.False(t, id1.Labels.Has(labels.ParseLabel("cidr:10.0.0.5/32")))

	id2 := IPIdentityCache.IdentityAllocator.LookupIdentityByID(ctx, nid2)
	assert.NotNil(t, id2)
	assert.True(t, id2.Labels.HasRemoteNodeLabel())
	assert.False(t, id2.Labels.HasKubeAPIServerLabel())
	assert.False(t, id2.Labels.Has(labels.ParseLabel("cidr:10.0.0.4/32")))
	assert.True(t, id2.Labels.Has(labels.ParseLabel("cidr:10.0.0.5/32")))

	// Remove remote-node label, ensure transition to local cidr identity space
	IPIdentityCache.metadata.remove(inClusterPrefix, "node-uid", overrideIdentity(false), labels.LabelRemoteNode)
	IPIdentityCache.metadata.remove(inClusterPrefix2, "node-uid", overrideIdentity(false), labels.LabelRemoteNode)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix, inClusterPrefix2})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)

	nid1 = IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID
	nid2 = IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID
	assert.Equal(t, identity.IdentityScopeLocal, nid1.Scope())
	assert.Equal(t, identity.IdentityScopeLocal, nid2.Scope())

	id1 = IPIdentityCache.IdentityAllocator.LookupIdentityByID(ctx, nid1)
	assert.NotNil(t, id1)
	assert.False(t, id1.Labels.HasRemoteNodeLabel())
	assert.True(t, id1.Labels.HasKubeAPIServerLabel())
	assert.True(t, id1.Labels.Has(labels.ParseLabel("cidr:10.0.0.4/32")))
	assert.False(t, id1.Labels.Has(labels.ParseLabel("cidr:10.0.0.5/32")))

	id2 = IPIdentityCache.IdentityAllocator.LookupIdentityByID(ctx, nid2)
	assert.NotNil(t, id2)
	assert.False(t, id2.Labels.HasRemoteNodeLabel())
	assert.False(t, id2.Labels.HasKubeAPIServerLabel())
	assert.False(t, id2.Labels.Has(labels.ParseLabel("cidr:10.0.0.4/32")))
	assert.True(t, id2.Labels.Has(labels.ParseLabel("cidr:10.0.0.5/32")))

	// Clean up.
	IPIdentityCache.metadata.remove(inClusterPrefix, "node-uid-cidr", overrideIdentity(false), labels.Labels{})
	IPIdentityCache.metadata.remove(inClusterPrefix2, "node-uid-cidr", overrideIdentity(false), labels.Labels{})
	IPIdentityCache.metadata.remove(inClusterPrefix, "kube-uid", overrideIdentity(false), labels.LabelKubeAPIServer)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix, inClusterPrefix2})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.metadata.m, 1)

	// Assert that an upsert for reserved:health label results in only the
	// reserved health ID.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Local, "node-uid", labels.LabelHealth)
	assert.Len(t, IPIdentityCache.metadata.m, 2)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityHealth, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID)

	// Assert that an upsert for reserved:ingress label results in only the
	// reserved ingress ID.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix2, source.Local, "node-uid", labels.LabelIngress)
	assert.Len(t, IPIdentityCache.metadata.m, 3)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix2})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityIngress, IPIdentityCache.ipToIdentityCache["10.0.0.5/32"].ID)
	// Clean up.
	IPIdentityCache.metadata.remove(inClusterPrefix2, "node-uid", overrideIdentity(false), labels.LabelIngress)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix2})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.metadata.m, 2)

	// Assert that a CIDR identity can be overridden automatically (without
	// overrideIdentity=true) when the prefix becomes associated with an entity
	// within the cluster.
	IPIdentityCache.metadata.upsertLocked(aPrefix, source.Generated, "cnp-uid", labels.LabelWorld)
	assert.Len(t, IPIdentityCache.metadata.m, 3)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{aPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	assert.True(t, IPIdentityCache.ipToIdentityCache["100.4.16.32/32"].ID.HasLocalScope())
	IPIdentityCache.metadata.upsertLocked(aPrefix, source.CustomResource, "node-uid", labels.LabelRemoteNode)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{aPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 3)
	assert.False(t, IPIdentityCache.ipToIdentityCache["100.4.16.32/32"].ID.HasLocalScope())

	// Assert that, in dual stack mode, an upsert for reserved:world-ipv4 label results in only the
	// reserved world-ipv4 ID.
	IPIdentityCache.metadata.upsertLocked(allIPv4CIDRsPrefix, source.Local, "daemon-uid", labels.LabelWorldIPv4)
	assert.Len(t, IPIdentityCache.metadata.m, 4)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{allIPv4CIDRsPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 4)
	assert.False(t, IPIdentityCache.ipToIdentityCache[ipv4All].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityWorldIPv4, IPIdentityCache.ipToIdentityCache[ipv4All].ID)

	// Assert that, in dual stack mode, an upsert for reserved:world-ipv6 label results in only the
	// reserved world-ipv6 ID.
	IPIdentityCache.metadata.upsertLocked(allIPv6CIDRsPrefix, source.Local, "daemon-uid", labels.LabelWorldIPv6)
	assert.Len(t, IPIdentityCache.metadata.m, 5)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{allIPv6CIDRsPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 5)
	assert.False(t, IPIdentityCache.ipToIdentityCache[ipv6All].ID.HasLocalScope())
	assert.Equal(t, identity.ReservedIdentityWorldIPv6, IPIdentityCache.ipToIdentityCache[ipv6All].ID)

	// Assert that, in ipv4-only mode, an upsert for reserved:world label results in only the
	// reserved world ID.
	option.Config.EnableIPv6 = false
	IPIdentityCache.metadata.upsertLocked(allIPv4CIDRsPrefix, source.Local, "daemon-uid", labels.LabelWorld)
	assert.Len(t, IPIdentityCache.metadata.m, 5)
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{allIPv4CIDRsPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
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

	injectLabels := func(ip cmtypes.PrefixCluster) {
		t.Helper()
		remaining, hostChanged, err := IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{ip})
		assert.NoError(t, err)
		assert.True(t, hostChanged)
		assert.Empty(t, remaining)
	}

	idIs := func(ip cmtypes.PrefixCluster, id identity.NumericIdentity) {
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

	// Verify that .4 now has just kube-apiserver and world
	idIs(inClusterPrefix, identity.IdentityScopeLocal) // the first CIDR identity
	id := PolicyHandler.identities[identity.IdentityScopeLocal]
	assert.True(t, id.Has("reserved.kube-apiserver"))
	assert.True(t, id.Has("reserved.world-ipv4"), "labels: %s", id.String())

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
	// - NameManager.updateDNSIPs calls UpsertMetadataBatch() when then inserts them
	//   via TriggerLabelInjection.
	fqdnResourceID := types.NewResourceID(types.ResourceKindDaemon, "", "fqdn-name-manager")
	prefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("172.19.0.5/32"))
	IPIdentityCache.metadata.upsertLocked(prefix, source.Generated, fqdnResourceID)
	remaining, hostChanged, err := IPIdentityCache.doInjectLabels(context.Background(), []cmtypes.PrefixCluster{prefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)

	// sanity check: ensure the cidr is correctly in the ipcache
	wantID := identity.IdentityScopeLocal
	id, ok := IPIdentityCache.LookupByIP(prefix.String())
	assert.True(t, ok)
	assert.Equal(t, wantID, id.ID)

	// Simulate the first half of UpsertMetadata -- insert the labels only in to the metadata cache
	// This is to "force" a race condition
	resource := types.NewResourceID(
		types.ResourceKindEndpoint, "default", "kubernetes")
	IPIdentityCache.metadata.upsertLocked(prefix, source.KubeAPIServer, resource, labels.LabelKubeAPIServer)

	// Now, emulate a ToServices policy, which calls UpsertMetadataBatch
	IPIdentityCache.metadata.upsertLocked(prefix, source.CustomResource, "policy-uid", labels.GetCIDRLabels(prefix.AsPrefix()))

	// Now, the second half of UpsertMetadata -- identity injection
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(context.Background(), []cmtypes.PrefixCluster{prefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)

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

	IPIdentityCache.metadata.upsertLocked(
		cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("2.1.1.1/32")),
		source.Generated, "gen-uid", labels.LabelWorld,
	)
	IPIdentityCache.metadata.upsertLocked(
		cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("3.1.1.1/32")),
		source.Generated, "gen-uid-2", labels.LabelWorld,
	)

	assert.Len(t, IPIdentityCache.metadata.filterByLabels(labels.LabelKubeAPIServer), 1)
	assert.Len(t, IPIdentityCache.metadata.filterByLabels(labels.LabelWorld), 2)
}

func TestRemoveLabelsFromIPs(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()
	ctx := context.Background()

	assert.Len(t, IPIdentityCache.metadata.m, 1)
	remaining, hostChanged, err := IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.True(t, hostChanged)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	// Attempting to remove a label for a ResourceID which does not exist
	// should not remove anything.
	IPIdentityCache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer, map[cmtypes.PrefixCluster]struct{}{},
		"foo")
	assert.Len(t, IPIdentityCache.metadata.m, 1)
	assert.Contains(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels(), labels.IDNameKubeAPIServer)

	IPIdentityCache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer, map[cmtypes.PrefixCluster]struct{}{},
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
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.True(t, hostChanged)
	id := IPIdentityCache.IdentityAllocator.LookupIdentityByID(
		context.TODO(),
		identity.IdentityScopeLocal, // we assume first local ID
	)
	assert.NotNil(t, id)
	assert.Equal(t, 1, id.ReferenceCount)

	// Simulate adding CIDR policy by simulating UpsertMetadataBatch
	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.CustomResource, "policy-uid", labels.GetCIDRLabels(worldPrefix.AsPrefix()))
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Zero(t, remaining)
	assert.False(t, hostChanged)
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
		labels.LabelKubeAPIServer, map[cmtypes.PrefixCluster]struct{}{},
		"kube-uid")
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.NotContains(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels(), labels.IDNameKubeAPIServer)
	nid, exists = IPIdentityCache.LookupByPrefix(worldPrefix.String())
	assert.True(t, exists)
	id = IPIdentityCache.IdentityAllocator.LookupIdentityByID(
		context.TODO(),
		nid.ID,
	)
	assert.Equal(t, 1, id.ReferenceCount) // CIDR policy is left

	// Simulate removing CIDR policy.
	IPIdentityCache.RemoveMetadata(worldPrefix, "policy-uid", labels.Labels{})
	remaining, hostChanged, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.False(t, hostChanged)
	assert.Empty(t, IPIdentityCache.metadata.m[worldPrefix].ToLabels())
	nid, exists = IPIdentityCache.LookupByPrefix(worldPrefix.String())
	assert.False(t, exists)
	id = IPIdentityCache.IdentityAllocator.LookupIdentityByID(
		context.TODO(),
		id.ID, // check old ID is deallocated
	)
	assert.Nil(t, id)
}

func TestRemoveAPIServerIdentityExternal(t *testing.T) {
	cancel := setupTestExternalAPIServer(t)
	defer cancel()
	ctx := context.Background()

	assert.Len(t, IPIdentityCache.metadata.m, 1)
	remaining, _, err := IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	IPIdentityCache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer, map[cmtypes.PrefixCluster]struct{}{},
		"kube-uid")
	remaining, _, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, IPIdentityCache.metadata.m)
	assert.Empty(t, remaining)
}

func TestOverrideIdentity(t *testing.T) {
	allocator := testidentity.NewMockIdentityAllocator(nil)

	// pre-allocate override identities
	fooLabels := labels.NewLabelsFromSortedList("k8s:name=foo")
	fooID, isNew, err := allocator.AllocateIdentity(context.TODO(), fooLabels, false, identity.InvalidIdentity)
	assert.Equal(t, 1, fooID.ReferenceCount)
	assert.NoError(t, err)
	assert.True(t, isNew)

	barLabels := labels.NewLabelsFromSortedList("k8s:name=bar")
	barID, isNew, err := allocator.AllocateIdentity(context.TODO(), barLabels, false, identity.InvalidIdentity)
	assert.Equal(t, 1, fooID.ReferenceCount)
	assert.NoError(t, err)
	assert.True(t, isNew)

	ipc := NewIPCache(&Configuration{
		Logger:            hivetest.Logger(t),
		IdentityAllocator: allocator,
		PolicyHandler:     newMockUpdater(),
		DatapathHandler:   &mockTriggerer{},
	})
	ctx := context.Background()

	// Create CIDR identity from labels
	ipc.metadata.upsertLocked(worldPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	remaining, _, err := ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	id, ok := ipc.LookupByPrefix(worldPrefix.String())
	assert.True(t, ok)
	assert.True(t, id.ID.HasLocalScope())
	assert.False(t, id.ID.IsReservedIdentity())

	// Force an identity override
	ipc.metadata.upsertLocked(worldPrefix, source.CustomResource, "cep-uid", overrideIdentity(true), fooLabels)
	remaining, _, err = ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	id, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.True(t, ok)
	assert.Equal(t, 2, fooID.ReferenceCount)
	assert.Equal(t, id.ID, fooID.ID)

	// Remove identity override from prefix, should assign a CIDR identity again
	ipc.metadata.remove(worldPrefix, "cep-uid", overrideIdentity(true), fooLabels)
	remaining, _, err = ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	id, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.True(t, ok)
	assert.True(t, id.ID.HasLocalScope())
	assert.False(t, id.ID.IsReservedIdentity())
	assert.Equal(t, 1, fooID.ReferenceCount)

	// Remove remaining labels from prefix, this should remove the entry
	ipc.metadata.remove(worldPrefix, "kube-uid", labels.LabelKubeAPIServer)
	remaining, _, err = ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	_, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.False(t, ok)

	// Create a new entry again via override
	ipc.metadata.upsertLocked(worldPrefix, source.CustomResource, "cep-uid", overrideIdentity(true), barLabels)
	remaining, _, err = ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	// Add labels, those will be ignored due to override
	ipc.metadata.upsertLocked(worldPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	remaining, _, err = ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	id, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.True(t, ok)
	assert.Equal(t, id.ID, barID.ID)
	assert.Equal(t, 2, barID.ReferenceCount)

	// Remove all metadata at once, this should remove the whole entry
	ipc.metadata.remove(worldPrefix, "kube-uid", labels.LabelKubeAPIServer)
	ipc.metadata.remove(worldPrefix, "cep-uid", overrideIdentity(true), barLabels)
	remaining, _, err = ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{worldPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	_, ok = ipc.LookupByPrefix(worldPrefix.String())
	assert.Equal(t, 1, barID.ReferenceCount)
	assert.False(t, ok)
}

func TestUpsertMetadataTunnelPeerAndEncryptKey(t *testing.T) {
	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeTunnel

	prevEncryption := option.Config.EnableIPSec
	defer func() { option.Config.EnableIPSec = prevEncryption }()
	option.Config.EnableIPSec = true

	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid",
		types.TunnelPeer{Addr: netip.MustParseAddr("192.168.1.100")},
		types.EncryptKey(7))
	remaining, _, err := IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	ip, key := IPIdentityCache.getHostIPCacheRLocked(inClusterPrefix.String())
	assert.Equal(t, "192.168.1.100", ip.String())
	assert.Equal(t, uint8(7), key)

	// Assert that an entry with a weaker source (and from a different
	// resource) should trigger a conflict warning.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.Generated, "generated-uid",
		types.TunnelPeer{Addr: netip.MustParseAddr("192.168.1.101")},
		types.EncryptKey(6))
	assert.True(t, IPIdentityCache.metadata.m[inClusterPrefix]["generated-uid"].shouldLogConflicts())
	_, _, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix})
	assert.NoError(t, err)

	// Remove the entry with the encryptKey=7 and encryptKey=6.
	IPIdentityCache.metadata.remove(inClusterPrefix, "node-uid", types.EncryptKey(7))
	IPIdentityCache.metadata.remove(inClusterPrefix, "generated-uid", types.EncryptKey(6))
	remaining, _, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	// Assert that there should only be the entry with the tunnelPeer set.
	ip, key = IPIdentityCache.getHostIPCacheRLocked(inClusterPrefix.String())
	assert.Equal(t, uint8(0), key)

	// The following tests whether an entry with a high priority source
	// (KubeAPIServer) allows lower priority sources to set the TunnelPeer and
	// EncryptKey.
	//
	// Start with a KubeAPIServer entry with just labels.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.KubeAPIServer, "kube-uid",
		labels.LabelKubeAPIServer,
	)
	remaining, _, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix})
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	// Add TunnelPeer and EncryptKey from the CustomResource source.
	IPIdentityCache.metadata.upsertLocked(inClusterPrefix, source.CustomResource, "node-uid",
		labels.LabelRemoteNode,
		types.TunnelPeer{Addr: netip.MustParseAddr("192.168.1.101")},
		types.EncryptKey(6),
	)
	_, _, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix})
	assert.NoError(t, err)
	ip, key = IPIdentityCache.getHostIPCacheRLocked(inClusterPrefix.String())
	assert.Equal(t, "192.168.1.101", ip.String())
	assert.Equal(t, uint8(6), key)
}

// TestRequestIdentity checks that the identity restoration mechanism works as expected:
// -- requested numeric identities are utilized
// -- if two prefixes somehow collide, everything still works
func TestRequestIdentity(t *testing.T) {
	cancel := setupTest(t)
	cancel()

	injectLabels := func(prefixes ...cmtypes.PrefixCluster) {
		t.Helper()
		remaining, _, err := IPIdentityCache.doInjectLabels(context.Background(), prefixes)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
	}

	hasIdentity := func(prefix cmtypes.PrefixCluster, nid identity.NumericIdentity) {
		t.Helper()
		id, _ := IPIdentityCache.LookupByPrefix(prefix.String())
		assert.Equal(t, nid, id.ID)
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

// Test that doInjectLabels does the right thing when one allocation fails
func TestInjectFailedAllocate(t *testing.T) {
	cancel := setupTest(t)
	ctx := IPIdentityCache.Context
	ipc := IPIdentityCache
	cancel()

	ipc.metadata.upsertLocked(inClusterPrefix, source.Restored, "daemon-uid", labels.GetCIDRLabels(inClusterPrefix.AsPrefix()))
	ipc.metadata.upsertLocked(inClusterPrefix2, source.Restored, "daemon-uid", labels.GetCIDRLabels(inClusterPrefix2.AsPrefix()))

	Allocator.Reject(labels.GetCIDRLabels(inClusterPrefix.AsPrefix()))
	remaining, _, err := ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix, inClusterPrefix2})
	require.Error(t, err)
	require.Len(t, remaining, 2)

	Allocator.Unreject(labels.GetCIDRLabels(inClusterPrefix.AsPrefix()))
	Allocator.Reject(labels.GetCIDRLabels(inClusterPrefix2.AsPrefix()))

	remaining, _, err = ipc.doInjectLabels(ctx, []cmtypes.PrefixCluster{inClusterPrefix, inClusterPrefix2})
	require.Error(t, err)
	require.Len(t, remaining, 1)
}

// Test that handleLabelInjection() correctly splits in to chunks
// and handles error cases.
func TestHandleLabelInjection(t *testing.T) {
	oldChunkSize := chunkSize
	defer func() {
		chunkSize = oldChunkSize
	}()
	chunkSize = 1

	cancel := setupTest(t)
	ctx := IPIdentityCache.Context
	ipc := IPIdentityCache
	cancel()

	ipc.metadata.upsertLocked(inClusterPrefix, source.Restored, "daemon-uid", labels.GetCIDRLabels(inClusterPrefix.AsPrefix()))
	ipc.metadata.upsertLocked(inClusterPrefix2, source.Restored, "daemon-uid", labels.GetCIDRLabels(inClusterPrefix2.AsPrefix()))
	ipc.metadata.enqueuePrefixUpdates(inClusterPrefix, inClusterPrefix2)

	// Removing the allocator will cause injection to fail
	ipc.IdentityAllocator = nil

	// Trigger label injection, we should see failure
	err := ipc.handleLabelInjection(ctx)

	// Ensure that no prefixes have been lost
	require.Len(t, ipc.metadata.queuedPrefixes, 2)
	require.Equal(t, uint64(0), ipc.metadata.injectedRevision)
	require.Error(t, err)

	// enable allocation, but reject one of the prefixes
	ipc.IdentityAllocator = Allocator
	Allocator.Reject(labels.GetCIDRLabels(inClusterPrefix.AsPrefix()))

	err = ipc.handleLabelInjection(ctx)
	// May be 1 or 2 pending prefixes, depending on which came first
	require.GreaterOrEqual(t, len(ipc.metadata.queuedPrefixes), 1)
	require.Equal(t, uint64(0), ipc.metadata.injectedRevision)
	require.Error(t, err)
	require.NotContains(t, ipc.ipToIdentityCache, inClusterPrefix.String())

	Allocator.Unreject(labels.GetCIDRLabels(inClusterPrefix.AsPrefix()))

	// No more issues, we should succeed
	err = ipc.handleLabelInjection(ctx)
	require.Empty(t, ipc.metadata.queuedPrefixes)
	require.Equal(t, uint64(3), ipc.metadata.injectedRevision)
	// ensure all IPs are in the ipcache
	require.Contains(t, ipc.ipToIdentityCache, inClusterPrefix.String())
	require.Contains(t, ipc.ipToIdentityCache, inClusterPrefix2.String())
	require.NoError(t, err)
}

func TestMetadataRevision(t *testing.T) {
	logger := hivetest.Logger(t)
	m := newMetadata(logger)

	p1 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("1.1.1.1/32"))
	p2 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("1::1/128"))

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
	logger := hivetest.Logger(t)
	m := newMetadata(logger)

	_, wantRev := m.dequeuePrefixUpdates()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err := m.waitForRevision(context.TODO(), wantRev)
		require.NoError(t, err)
		wg.Done()
	}()

	m.setInjectedRevision(wantRev)
	wg.Wait()

	// Test cancellation
	_, wantRev = m.dequeuePrefixUpdates()
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Millisecond)
	t.Cleanup(cancel)
	err := m.waitForRevision(ctx, wantRev)
	require.Error(t, err)
}

func TestUpsertMetadataInheritedCIDRPrefix(t *testing.T) {
	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	// Simulate CIDR policy
	parent := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.0/8"))
	prefixes := IPIdentityCache.metadata.upsertLocked(parent, source.Kubernetes, "cidr-policy", labels.GetCIDRLabels(parent.AsPrefix()))

	remaining, _, err := IPIdentityCache.doInjectLabels(ctx, prefixes)
	require.NoError(t, err)
	require.Empty(t, remaining)

	// Simulate first FQDN lookup
	fqdnLabels := labels.NewLabelsFromSortedList("fqdn:*.internal")
	child := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.0.1/32"))
	prefixes = IPIdentityCache.metadata.upsertLocked(child, source.Generated, "fqdn-lookup", fqdnLabels)
	remaining, _, err = IPIdentityCache.doInjectLabels(ctx, prefixes)
	require.NoError(t, err)
	require.Empty(t, remaining)

	id, ok := IPIdentityCache.LookupByPrefix(child.String())
	ident := IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.TODO(), id.ID)
	require.True(t, ok)
	require.NotNil(t, ident)
	require.Equal(t, "cidr:10.0.0.0/8,fqdn:*.internal,reserved:world-ipv4", ident.Labels.String())

	// Add second fqdn ip, it should get the same identity
	sibling := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.0.2/32"))
	prefixes = IPIdentityCache.metadata.upsertLocked(sibling, source.Generated, "fqdn-lookup", fqdnLabels)
	remaining, _, err = IPIdentityCache.doInjectLabels(ctx, prefixes)
	require.NoError(t, err)
	require.Empty(t, remaining)

	newID, ok := IPIdentityCache.LookupByPrefix(child.String())
	require.True(t, ok)
	require.Equal(t, id.ID, newID.ID)

	// Removing the parent should update the child identities
	prefixes = IPIdentityCache.metadata.remove(parent, "cidr-policy", labels.Labels{})
	remaining, _, err = IPIdentityCache.doInjectLabels(ctx, prefixes)
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	// Check that identities for both children have changed
	id, ok = IPIdentityCache.LookupByPrefix(child.String())
	ident = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.TODO(), id.ID)
	require.True(t, ok)
	require.NotNil(t, ident)
	require.Equal(t, "fqdn:*.internal,reserved:world-ipv4", ident.Labels.String())
	newID, ok = IPIdentityCache.LookupByPrefix(child.String())
	require.True(t, ok)
	require.Equal(t, id.ID, newID.ID)

	// Re-add different CIDR policy
	parent = cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.0.0/16"))
	prefixes = IPIdentityCache.metadata.upsertLocked(parent, source.Kubernetes, "cidr-policy", labels.GetCIDRLabels(parent.AsPrefix()))
	remaining, _, err = IPIdentityCache.doInjectLabels(ctx, prefixes)
	require.NoError(t, err)
	require.Empty(t, remaining)

	// Check that identities for both children have changed yet again
	id, ok = IPIdentityCache.LookupByPrefix(child.String())
	ident = IPIdentityCache.IdentityAllocator.LookupIdentityByID(context.TODO(), id.ID)
	require.True(t, ok)
	require.NotNil(t, ident)
	require.Equal(t, "cidr:10.10.0.0/16,fqdn:*.internal,reserved:world-ipv4", ident.Labels.String())
	newID, ok = IPIdentityCache.LookupByPrefix(child.String())
	require.True(t, ok)
	require.Equal(t, id.ID, newID.ID)

	// Remove fqdn-lookups
	prefixes = IPIdentityCache.metadata.remove(child, "fqdn-lookup", labels.Labels{})
	prefixes = append(prefixes, IPIdentityCache.metadata.remove(sibling, "fqdn-lookup", labels.Labels{})...)
	remaining, _, err = IPIdentityCache.doInjectLabels(ctx, prefixes)
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	_, ok = IPIdentityCache.LookupByPrefix(child.String())
	require.False(t, ok)
	_, ok = IPIdentityCache.LookupByPrefix(sibling.String())
	require.False(t, ok)

	ident = IPIdentityCache.IdentityAllocator.LookupIdentity(context.TODO(), ident.Labels)
	assert.Nil(t, ident)
}

func TestResolveIdentity(t *testing.T) {
	type sm map[string]string

	for i, tc := range []struct {
		prefixes    sm
		expected    sm
		expectedIDs map[string]identity.NumericIdentity

		cidrMatchNode bool
	}{
		// case 0: a /24 cidr, a /32 fqdn within that cidr, and a /32 fqdn outside that cidr
		{
			prefixes: sm{
				"10.0.0.0/24": "cidr:10.0.0.0/24=;reserved:world-ipv4",
				"10.0.0.1/32": "fqdn:example.com=",
				"10.0.1.1/32": "fqdn:example.com=",
			},
			expected: sm{
				"10.0.0.0/24": "cidr:10.0.0.0/24=;reserved:world-ipv4",
				"10.0.0.1/32": "cidr:10.0.0.0/24=;fqdn:example.com=;reserved:world-ipv4",
				"10.0.1.1/32": "fqdn:example.com=;reserved:world-ipv4",
			},
		},

		// case 1: nodes, node cidr selection disabled
		// a /24 cidr, a remote node, and some FQDNs that happen to point to that node.
		// because FQDNs are equivalent to CIDRs, and nodes cannot be selected by CIDRs,
		// they should not have that label
		{
			prefixes: sm{
				"10.0.0.0/24": "cidr:10.0.0.0/24=;reserved:world-ipv4",
				"10.0.0.1/32": "reserved:remote-node=",
				"10.0.1.1/32": "reserved:remote-node=;fqdn:example.com=",
			},
			expected: sm{
				"10.0.0.0/24": "cidr:10.0.0.0/24=;reserved:world-ipv4",
				"10.0.0.1/32": "reserved:remote-node=",
				"10.0.1.1/32": "reserved:remote-node=",
			},
			expectedIDs: map[string]identity.NumericIdentity{
				"10.0.0.1/32": identity.ReservedIdentityRemoteNode,
				"10.0.1.1/32": identity.ReservedIdentityRemoteNode,
			},
		},

		// case 2: nodes, node cidr selection enabled
		{
			prefixes: sm{
				"10.0.0.0/24": "cidr:10.0.0.0/24;reserved:world-ipv4",
				// the CIDR label is injected directly by the NodeManager
				"10.0.0.1/32": "cidr:10.0.0.1/32;reserved:remote-node",
				"10.0.1.1/32": "cidr:10.0.1.1/32;reserved:remote-node;fqdn:example.com",
			},
			expected: sm{
				"10.0.0.0/24": "cidr:10.0.0.0/24=;reserved:world-ipv4",
				"10.0.0.1/32": "cidr:10.0.0.1/32;reserved:remote-node=",
				"10.0.1.1/32": "cidr:10.0.1.1/32;reserved:remote-node=;fqdn:example.com=",
			},

			cidrMatchNode: true,
		},

		// case 3: reserved identities must never get CIDR, CIDRGroup, or FQDN labels
		{
			prefixes: sm{
				"10.0.0.0/8":  "cidrgroup:foo;reserved:world-ipv4",
				"10.0.0.0/24": "cidr:10.0.0.0/24;reserved:world-ipv4",
				"10.0.0.1/32": "cidr:10.0.0.1/32;reserved:ingress=",
				"10.0.0.2/32": "cidr:10.0.0.2/32;fqdn:example.com;reserved:health=",
			},
			expected: sm{
				"10.0.0.0/24": "cidrgroup:foo;cidr:10.0.0.0/24=;reserved:world-ipv4",
				"10.0.0.1/32": "reserved:ingress=",
				"10.0.0.2/32": "reserved:health=",
			},
			expectedIDs: map[string]identity.NumericIdentity{
				"10.0.0.1/32": identity.ReservedIdentityIngress,
				"10.0.0.2/32": identity.ReservedIdentityHealth,
			},
		},

		// case 4: CIDR groups
		{
			prefixes: sm{
				"10.0.0.0/8":  "cidrgroup:foo;reserved:world-ipv4",
				"10.0.0.0/24": "cidrgroup:bar;reserved:world-ipv4",
				"10.0.0.1/32": "fqdn:example.com=",
				"10.0.1.1/32": "fqdn:example.com=",
			},
			expected: sm{
				"10.0.0.0/24": "cidrgroup:bar;cidrgroup:foo;reserved:world-ipv4",
				"10.0.0.1/32": "cidrgroup:bar;cidrgroup:foo;fqdn:example.com;reserved:world-ipv4",
				"10.0.1.1/32": "cidrgroup:foo;fqdn:example.com;reserved:world-ipv4",
			},
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			oldPolicyConfig := option.Config.PolicyCIDRMatchMode
			t.Cleanup(func() {
				option.Config.PolicyCIDRMatchMode = oldPolicyConfig
			})
			if tc.cidrMatchNode {
				option.Config.PolicyCIDRMatchMode = []string{"nodes"}
			} else {
				option.Config.PolicyCIDRMatchMode = []string{}
			}

			cancel := setupTest(t)
			t.Cleanup(cancel)

			for pfx, lstr := range tc.prefixes {
				lbls := labels.NewLabelsFromSortedList(lstr)
				prefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix(pfx))
				IPIdentityCache.metadata.upsertLocked(prefix, source.Generated, "tc", lbls)
			}

			for pfx, lstr := range tc.expected {
				lbls := labels.NewLabelsFromSortedList(lstr)
				prefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix(pfx))
				info := IPIdentityCache.metadata.getLocked(prefix)
				require.NotNil(t, info)
				id, _, err := IPIdentityCache.resolveIdentity(context.Background(), prefix, info, 0)
				require.NoError(t, err)

				if expectedNID, ok := tc.expectedIDs[pfx]; ok {
					require.Equal(t, expectedNID, id.ID)
				}

				require.Equal(t, lbls, id.Labels, lstr)
			}
		})
	}
}

// TestUpsertMetadataCIDRGroup tests that cidr group labels
// propagate down to all CIDRs
func TestUpsertMetadataCIDRGroup(t *testing.T) {
	p1 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.0/8"))
	p2 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.0/16"))
	p3 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.0/24"))
	p4 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.0/25"))
	p5 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.0/26"))
	p6 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.0/27"))

	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	IPIdentityCache.metadata.upsertLocked(p1, source.Generated, "r1", labels.NewLabelsFromSortedList("cidrgroup:a="))
	IPIdentityCache.metadata.upsertLocked(p2, source.Generated, "r1", labels.NewLabelsFromSortedList("cidrgroup:b="))
	IPIdentityCache.metadata.upsertLocked(p3, source.Generated, "r1", labels.NewLabelsFromSortedList("cidrgroup:c="))

	_, _, err := IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{p1, p2, p3})
	require.NoError(t, err)

	hasLabels := func(prefix netip.Prefix, wantl string) {
		t.Helper()
		nid, ok := IPIdentityCache.LookupByPrefixRLocked(prefix.String())
		require.True(t, ok)
		id := IPIdentityCache.LookupIdentityByID(ctx, nid.ID)
		require.NotNil(t, id)

		wantlbls := labels.NewLabelsFromSortedList(wantl)
		require.Equal(t, wantlbls, id.Labels)
	}

	hasLabels(p1.AsPrefix(), "cidrgroup:a=;reserved:world-ipv4=")
	hasLabels(p2.AsPrefix(), "cidrgroup:a=;cidrgroup:b=;reserved:world-ipv4=")
	hasLabels(p3.AsPrefix(), "cidrgroup:a=;cidrgroup:b=;cidrgroup:c=;reserved:world-ipv4=")

	// Now, test overlapping CIDR, CIDRGroup, and FQDN labels
	IPIdentityCache.metadata.upsertLocked(p4, source.Generated, "r1", labels.GetCIDRLabels(p4.AsPrefix()))
	IPIdentityCache.metadata.upsertLocked(p5, source.Generated, "r1", labels.GetCIDRLabels(p5.AsPrefix()))
	IPIdentityCache.metadata.upsertLocked(p6, source.Generated, "r1", labels.NewLabelsFromSortedList("fqdn:*.cilium.io="))

	_, _, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{p4, p5, p6})
	require.NoError(t, err)

	hasLabels(p4.AsPrefix(), "cidr:10.0.0.0/25=;cidrgroup:a=;cidrgroup:b=;cidrgroup:c=;reserved:world-ipv4=")
	hasLabels(p5.AsPrefix(), "cidr:10.0.0.0/26=;cidrgroup:a=;cidrgroup:b=;cidrgroup:c=;reserved:world-ipv4=")
	hasLabels(p6.AsPrefix(), "cidr:10.0.0.0/26=;cidrgroup:a=;cidrgroup:b=;cidrgroup:c=;reserved:world-ipv4=;fqdn:*.cilium.io=")

}

func setupTest(t *testing.T) (cleanup func()) {
	t.Helper()
	logger := hivetest.Logger(t)

	ctx, cancel := context.WithCancel(context.Background())
	Allocator = testidentity.NewMockIdentityAllocator(nil)
	PolicyHandler = newMockUpdater()
	IPIdentityCache = NewIPCache(&Configuration{
		Context:           ctx,
		Logger:            logger,
		IdentityAllocator: Allocator,
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

func setupTestExternalAPIServer(t *testing.T) (cleanup func()) {
	t.Helper()
	logger := hivetest.Logger(t)

	ctx, cancel := context.WithCancel(context.Background())
	Allocator = testidentity.NewMockIdentityAllocator(nil)
	PolicyHandler = newMockUpdater()
	IPIdentityCache = NewIPCache(&Configuration{
		Context:           ctx,
		Logger:            logger,
		IdentityAllocator: Allocator,
		PolicyHandler:     PolicyHandler,
		DatapathHandler:   &mockTriggerer{},
	})

	IPIdentityCache.metadata.upsertLocked(worldPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServerExt)

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

func (m *mockUpdater) UpdateIdentities(added, deleted identity.IdentityMap, _ *sync.WaitGroup) (mutated bool) {
	for nid, lbls := range added {
		m.identities[nid] = lbls
		if nid == identity.ReservedIdentityHost {
			mutated = true
		}
	}

	for nid := range deleted {
		delete(m.identities, nid)
	}
	return mutated
}

type mockTriggerer struct{}

func (m *mockTriggerer) UpdatePolicyMaps(ctx context.Context, wg *sync.WaitGroup) *sync.WaitGroup {
	return wg
}

func Test_canonicalPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix cmtypes.PrefixCluster
		want   cmtypes.PrefixCluster
	}{
		{
			name:   "identity",
			prefix: cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.10.10/32")),
			want:   cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.10.10/32")),
		},
		{
			name:   "masked",
			prefix: cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.10.10/16")),
			want:   cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.0.0/16")),
		},
		{
			name:   "v4inv6",
			prefix: cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("::ffff:10.10.10.10/24")),
			want:   cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.10.0/24")),
		},
		{
			name:   "ipv6",
			prefix: cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("2001:db8::dead/32")),
			want:   cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("2001:db8::/32")),
		},
		{
			name:   "invalid",
			prefix: cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(netip.MustParseAddr("::ffff:10.10.10.10"), -1)),
			want:   cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(netip.MustParseAddr("::ffff:10.10.10.10"), -1)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, canonicalPrefix(tt.prefix), "canonicalPrefix(%v)", tt.prefix)
		})
	}
}

func Test_metadata_mergeParentLabels(t *testing.T) {
	tests := []struct {
		name       string
		existing   map[string]labels.Labels
		prefix     string
		wantLabels labels.Labels
	}{
		{
			name: "no self-match",
			existing: map[string]labels.Labels{
				"1.1.1.1/32": labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.1/32")),
			},
			prefix:     "1.1.1.1/32",
			wantLabels: labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.1/32")),
		},

		{
			name: "match first cidr parent",
			existing: map[string]labels.Labels{
				"1.1.1.1/32": labels.ParseLabelArray("fqdn:example.com").Labels(),
				"1.1.0.0/16": labels.GetCIDRLabels(netip.MustParsePrefix("1.1.0.0/16")),
				"1.0.0.0/8":  labels.GetCIDRLabels(netip.MustParsePrefix("1.0.0.0/8")),
			},
			prefix:     "1.1.1.1/32",
			wantLabels: labels.ParseLabelArray("reserved:world-ipv4", "cidr:1.1.0.0/16", "fqdn:example.com").Labels(),
		},

		{
			name: "merge all parent labelsl",
			existing: map[string]labels.Labels{
				"1.1.1.1/32": labels.ParseLabelArray("fqdn:example.com").Labels(),
				"1.1.0.0/16": labels.ParseLabelArray("cidr:1.1.0.0/16", "reserved:world-ipv4", "cidrgroup:foo").Labels(),
				"1.2.0.0/16": labels.ParseLabelArray("cidr:1.1.0.0/16", "reserved:world-ipv4", "cidrgroup:do-not-want").Labels(),
				"1.0.0.0/8":  labels.ParseLabelArray("cidr:1.0.0.0/8", "reserved:world-ipv4", "cidrgroup:bar").Labels(),
			},
			prefix:     "1.1.1.1/32",
			wantLabels: labels.ParseLabelArray("reserved:world-ipv4", "cidr:1.1.0.0/16", "fqdn:example.com", "cidrgroup:foo", "cidrgroup:bar").Labels(),
		},

		{
			name: "longest-match wins",
			existing: map[string]labels.Labels{
				"1.1.1.1/32": labels.ParseLabelArray("fqdn:example.com").Labels(),
				"1.1.0.0/16": labels.ParseLabelArray("cidr:1.1.0.0/16", "reserved:world-ipv4", "cidrgroup:foo=yes").Labels(),
				"1.0.0.0/8":  labels.ParseLabelArray("cidr:1.0.0.0/8", "reserved:world-ipv4", "cidrgroup:foo=no", "cidrgroup:bar").Labels(),
			},
			prefix:     "1.1.1.1/32",
			wantLabels: labels.ParseLabelArray("reserved:world-ipv4", "cidr:1.1.0.0/16", "fqdn:example.com", "cidrgroup:foo=yes", "cidrgroup:bar").Labels(),
		},
		{
			name: "match for non-canonical prefix",
			existing: map[string]labels.Labels{
				"1.1.0.0/16": labels.ParseLabelArray("cidr:1.1.0.0/16", "reserved:world-ipv4", "cidrgroup:foo=yes").Labels(),
			},
			prefix:     "::ffff:1.1.1.1/24",
			wantLabels: labels.ParseLabelArray("reserved:world-ipv4", "cidr:1.1.0.0/16", "cidrgroup:foo=yes").Labels(),
		},
		{
			name: "world",
			existing: map[string]labels.Labels{
				"1.1.0.0/16": labels.ParseLabelArray("cidr:1.1.0.0/16", "reserved:world-ipv4", "cidrgroup:foo=yes").Labels(),
				"0.0.0.0/0":  labels.ParseLabelArray("cidrgroup:my-world-group").Labels(),
			},
			prefix:     "1.1.1.1/32",
			wantLabels: labels.ParseLabelArray("reserved:world-ipv4", "cidr:1.1.0.0/16", "cidrgroup:foo=yes", "cidrgroup:my-world-group").Labels(),
		},

		{
			name: "ipv6",
			existing: map[string]labels.Labels{
				"fd00:ef::/48": labels.GetCIDRLabels(netip.MustParsePrefix("fd00:ef::/48")),
				"fd00:ef::/56": labels.GetCIDRLabels(netip.MustParsePrefix("fd00:ef::/56")),
				"fd00:ef::/40": labels.ParseLabelArray("cidrgroup:foo").Labels(),
			},
			prefix:     ("fd00:ef::1/128"),
			wantLabels: labels.ParseLabelArray("reserved:world-ipv6", "cidrgroup:foo", "cidr:fd00-ef--0/56").Labels(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			m := newMetadata(logger)
			for prefix, lbls := range tt.existing {
				pfx := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix(prefix))
				m.m[pfx] = prefixInfo{
					"resource": {
						labels: lbls,
					},
				}
			}

			pfx := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix(tt.prefix))

			lbls := m.getLocked(pfx).ToLabels()
			m.mergeParentLabels(lbls, pfx)

			assert.Equal(t, tt.wantLabels, lbls)
		})
	}
}

func TestIPCachePodCIDREntries(t *testing.T) {
	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeTunnel

	prevEncryption := option.Config.EnableIPSec
	defer func() { option.Config.EnableIPSec = prevEncryption }()
	option.Config.EnableIPSec = true

	cancel := setupTest(t)
	defer cancel()

	ctx := context.Background()

	// This emulates the upsert of fallback pod CIDR entry emitted by node manager
	podCIDR1 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.10.0.0/24"))
	podCIDR2 := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.20.30.40/32"))
	IPIdentityCache.metadata.upsertLocked(podCIDR1, source.CustomResource, "node-1",
		labels.NewLabelsFromSortedList("reserved:world-ipv4"),
		types.TunnelPeer{Addr: netip.MustParseAddr("192.168.1.101")},
		types.EncryptKey(6),
	)
	IPIdentityCache.metadata.upsertLocked(podCIDR2, source.CustomResource, "node-1",
		labels.NewLabelsFromSortedList("reserved:world-ipv4"),
		types.TunnelPeer{Addr: netip.MustParseAddr("192.168.1.101")},
		types.EncryptKey(6),
	)
	_, _, err := IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{podCIDR1, podCIDR2})
	require.NoError(t, err)

	ip, key := IPIdentityCache.getHostIPCache(podCIDR1.String())
	assert.Equal(t, "192.168.1.101", ip.String())
	assert.Equal(t, uint8(6), key)
	nid, ok := IPIdentityCache.LookupByPrefix(podCIDR1.String())
	assert.True(t, ok)
	assert.Equal(t, identity.ReservedIdentityWorldIPv4, nid.ID)

	ip, key = IPIdentityCache.getHostIPCache(podCIDR2.String())
	assert.Equal(t, "192.168.1.101", ip.String())
	assert.Equal(t, uint8(6), key)
	nid, ok = IPIdentityCache.LookupByPrefix(podCIDR2.String())
	assert.True(t, ok)
	assert.Equal(t, identity.ReservedIdentityWorldIPv4, nid.ID)

	// Emulate selecting pod CIDR in CIDRGroup
	IPIdentityCache.metadata.upsertLocked(podCIDR1, source.CustomResource, "r1",
		labels.NewLabelsFromSortedList("cidr:10.10.0.0/24=;cidrgroup:a="),
	)
	_, _, err = IPIdentityCache.doInjectLabels(ctx, []cmtypes.PrefixCluster{podCIDR1})
	require.NoError(t, err)

	// Assert identity labels have been merged
	nid, ok = IPIdentityCache.LookupByPrefix(podCIDR1.String())
	require.True(t, ok)
	id := IPIdentityCache.LookupIdentityByID(ctx, nid.ID)
	require.NotNil(t, id)
	wantlbls := labels.NewLabelsFromSortedList("cidr:10.10.0.0/24=;cidrgroup:a=;reserved:world-ipv4=")
	require.Equal(t, wantlbls, id.Labels)
	// Assert tunnel and encryption metadata has been preserved
	ip, key = IPIdentityCache.getHostIPCache(podCIDR1.String())
	assert.Equal(t, "192.168.1.101", ip.String())
	assert.Equal(t, uint8(6), key)

	// Emulate /32 pod CIDR being shadowed by CEP IP
	podIP2 := "10.20.30.40"
	podIdentity := identity.NumericIdentity(68)
	IPIdentityCache.Upsert(podIP2, nil, 0, nil, Identity{
		ID:     podIdentity,
		Source: source.KVStore,
	})
	nid, ok = IPIdentityCache.LookupByPrefix(podCIDR2.String())
	assert.True(t, ok)
	assert.Equal(t, podIdentity, nid.ID)

	// Unshadow PodCIDR2
	IPIdentityCache.Delete(podIP2, source.KVStore)
	nid, ok = IPIdentityCache.LookupByPrefix(podCIDR2.String())
	assert.True(t, ok)
	assert.Equal(t, identity.ReservedIdentityWorldIPv4, nid.ID)
}

func BenchmarkManyResources(b *testing.B) {
	logger := hivetest.Logger(b)
	m := newMetadata(logger)

	prefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("1.1.1.1/32"))
	lbls := labels.GetCIDRLabels(prefix.AsPrefix())

	for i := range b.N {
		resource := types.NewResourceID(types.ResourceKindCNP, fmt.Sprintf("namespace_%d", i), "my-policy")
		m.upsertLocked(prefix, source.Generated, resource, lbls)
	}
}

func BenchmarkManyCIDREntries(b *testing.B) {
	logger := hivetest.Logger(b)
	prevRoutingMode := option.Config.RoutingMode
	defer func() { option.Config.RoutingMode = prevRoutingMode }()
	option.Config.RoutingMode = option.RoutingModeNative

	allocator := testidentity.NewMockIdentityAllocator(nil)
	PolicyHandler = newMockUpdater()
	IPIdentityCache = NewIPCache(&Configuration{
		Logger:            logger,
		IdentityAllocator: allocator,
		PolicyHandler:     PolicyHandler,
		DatapathHandler:   &mockTriggerer{},
	})
	IPIdentityCache.metadata = newMetadata(logger)

	cidrs := generateUniqueCIDRs(1000)
	cidrLabels := make(map[cmtypes.PrefixCluster]labels.Labels, len(cidrs))
	for _, v := range cidrs {
		cidrLabels[v] = labels.GetCIDRLabels(v.AsPrefix())
	}
	half := len(cidrs) / 2
	removeHalf := cidrs[:half]
	insertHalf := cidrs[half:]

	revsLen := 1024
	revs := make([]uint64, 0, revsLen)
	var i int

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		mu := make([]MU, 0, len(cidrLabels))
		for cidr, lbls := range cidrLabels {
			mu = append(mu, MU{
				Prefix:   cidr,
				Source:   source.Generated,
				Resource: types.NewResourceID(types.ResourceKindCNP, fmt.Sprintf("namespace_%d", i), "my-policy"),
				Metadata: []IPMetadata{lbls},
				IsCIDR:   true,
			})
		}
		revs = append(revs, IPIdentityCache.UpsertMetadataBatch(mu...))
		i++
	}
	for _, rev := range revs {
		assert.NoError(b, IPIdentityCache.WaitForRevision(context.Background(), rev))
	}
	revsLen = len(revs)
	revs = make([]uint64, 0, revsLen)
	i = 1

	for b.Loop() {
		mu := make([]MU, 0, len(cidrLabels))
		for _, cidr := range removeHalf {
			mu = append(mu, MU{
				Prefix:   cidr,
				Source:   source.Generated,
				Resource: types.NewResourceID(types.ResourceKindCNP, fmt.Sprintf("namespace_%d", i), "my-policy"),
				Metadata: []IPMetadata{labels.Labels{}},
				IsCIDR:   true,
			})
		}
		revs = append(revs, IPIdentityCache.RemoveMetadataBatch(mu...))
		i++
	}
	for _, rev := range revs {
		assert.NoError(b, IPIdentityCache.WaitForRevision(context.Background(), rev))
	}
	revsLen = len(revs)
	revs = make([]uint64, 0, revsLen)
	i = 1

	for b.Loop() {
		mu := make([]MU, 0, len(cidrLabels))
		for _, cidr := range insertHalf {
			mu = append(mu, MU{
				Prefix:   cidr,
				Source:   source.Generated,
				Resource: types.NewResourceID(types.ResourceKindCNP, fmt.Sprintf("namespace_%d", i), "my-policy"),
				Metadata: []IPMetadata{cidrLabels[cidr]},
				IsCIDR:   true,
			})
		}
		revs = append(revs, IPIdentityCache.UpsertMetadataBatch(mu...))
		i++
	}
	for _, rev := range revs {
		assert.NoError(b, IPIdentityCache.WaitForRevision(context.Background(), rev))
	}
}

// generateUniqueCIDRs generates a specified number of unique CIDRs.
func generateUniqueCIDRs(n int) []cmtypes.PrefixCluster {
	rand.Seed(time.Now().UnixNano())

	unique := sets.New[cmtypes.PrefixCluster]()
	for unique.Len() < n {
		// Generate a random IP address
		ip := net.IPv4(
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
		)

		// Generate a random subnet mask (between 16 and 31)
		cidr := ip.String() + "/" + strconv.Itoa(rand.Intn(15)+17)
		unique = unique.Insert(cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix(cidr)))
	}

	return slices.Collect(maps.Keys(unique))
}
