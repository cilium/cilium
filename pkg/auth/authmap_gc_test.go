// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy"
)

func Test_authMapGarbageCollector_cleanupIdentities(t *testing.T) {
	ctx := context.TODO()

	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire}:        {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 3, remoteNodeID: 0, authType: policy.AuthTypeSpire}:        {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 11, remoteNodeID: 0, authType: policy.AuthTypeSpire}:       {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 12, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire}:       {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 11, remoteIdentity: 12, remoteNodeID: 0, authType: policy.AuthTypeAlwaysFail}: {expiration: time.Now().Add(5 * time.Minute)},
		},
	}
	gc := newAuthMapGC(logrus.New(), authMap, nil, nil)

	assert.Len(t, authMap.entries, 5)
	assert.Empty(t, gc.ciliumIdentitiesDiscovered)
	assert.Empty(t, gc.ciliumIdentitiesDeleted)
	assert.False(t, gc.ciliumIdentitiesSynced)

	err := gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, 1))
	assert.NoError(t, err, "Handling an identity change event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Identity changes should never modify the map directly")
	assert.Len(t, gc.ciliumIdentitiesDiscovered, 1, "Discovered identities should be kept in the internal state")

	err = gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, 2))
	assert.NoError(t, err, "Handling an identity change event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Identity changes should never modify the map directly")
	assert.Len(t, gc.ciliumIdentitiesDiscovered, 2, "Discovered identities should be kept in the internal state")

	err = gc.cleanupIdentities(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 5, "GC run before the initial sync should not delete any entries from the auth map")
	assert.Len(t, gc.ciliumIdentitiesDiscovered, 2, "GC run before the initial sync should not delete the discovered identities")

	err = gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeSync, 0))
	assert.NoError(t, err, "Handling an identity change event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Identity changes should never modify the map directly")
	assert.True(t, gc.ciliumIdentitiesSynced, "Identity changed sync event will mark the identities as synced")

	err = gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeDelete, 3))
	assert.NoError(t, err, "Handling an identity change event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Identity changes should never modify the map directly")
	assert.Len(t, gc.ciliumIdentitiesDeleted, 1, "Deleted identities after the sync and before the initial GC run should already be kept")

	err = gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, 3))
	assert.NoError(t, err, "Handling an identity change event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Identity changes should never modify the map directly")
	assert.Len(t, gc.ciliumIdentitiesDiscovered, 3, "Discovered identities after the sync event should be kept until the first GC run")

	err = gc.cleanupIdentities(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 1, "GC run after the initial sync should delete all entries which belong to deleted or non-discovered identities")
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire},
		"Auth map entry between ids 1->2 should be the only remaining entry, because the others are no longer existent or already deleted")
	assert.Nil(t, gc.ciliumIdentitiesDiscovered, "First GC run after the initial sync should reset the option to discover identities")
	assert.Empty(t, gc.ciliumIdentitiesDeleted, "GC runs should delete the successfully garbage collected entries from the list of deleted identities")

	err = gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, 13))
	assert.NoError(t, err, "Handling an identity change should never result in an error")
	assert.Len(t, authMap.entries, 1, "Identity changes should never modify the map directly")
	assert.Nil(t, gc.ciliumIdentitiesDiscovered, "Discovered identities after the first GC run should no longer be of any interest")

	err = gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeDelete, 2))
	assert.NoError(t, err, "Handling an identity change event should never result in an error")
	assert.Len(t, authMap.entries, 1, "Identity changes should never modify the map directly")
	assert.Len(t, gc.ciliumIdentitiesDeleted, 1, "Deleted identities should be kept for the next GC run")

	err = gc.cleanupIdentities(ctx)
	assert.NoError(t, err)
	assert.Empty(t, authMap.entries, "GC runs should delete all entries which belong to deleted identities")
	assert.Nil(t, gc.ciliumIdentitiesDiscovered)
	assert.Empty(t, gc.ciliumIdentitiesDeleted, "GC runs should delete the successfully garbage collected entries from the list of deleted identities")
}

func Test_authMapGarbageCollector_cleanupNodes(t *testing.T) {
	ctx := context.TODO()

	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 1, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 2, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 3, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 4, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
		},
	}
	gc := newAuthMapGC(logrus.New(), authMap, newFakeNodeIDHandler(map[uint16]string{
		1: "172.18.0.1",
		2: "172.18.0.2",
		3: "172.18.0.3",
		4: "172.18.0.4",
		5: "172.18.0.5",
	}), nil)

	assert.Len(t, authMap.entries, 5)
	assert.Len(t, gc.ciliumNodesDiscovered, 1, "Local node 0 is always present")
	assert.Empty(t, gc.ciliumNodesDeleted)
	assert.False(t, gc.ciliumNodesSynced)

	err := gc.NodeAdd(ciliumNodeEvent("172.18.0.1"))
	assert.NoError(t, err, "Handling a node event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Node events should never modify the map directly")
	assert.Len(t, gc.ciliumNodesDiscovered, 2, "Discovered nodes should be kept in the internal state")

	err = gc.NodeAdd(ciliumNodeEvent("172.18.0.2"))
	assert.NoError(t, err, "Handling a node event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Node events should never modify the map directly")
	assert.Len(t, gc.ciliumNodesDiscovered, 3, "Discovered nodes should be kept in the internal state")

	err = gc.cleanupIdentities(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 5, "GC run before the initial sync should not delete any entries from the auth map")
	assert.Len(t, gc.ciliumNodesDiscovered, 3, "GC run before the initial sync should not delete the discovered nodes")

	gc.ciliumNodesSynced = true // Node sync event will mark the nodes as synced

	err = gc.NodeDelete(ciliumNodeEvent("172.18.0.2"))
	assert.NoError(t, err, "Handling a node event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Node events should never modify the map directly")
	assert.Len(t, gc.ciliumNodesDeleted, 1, "Deleted nodes after the sync and before the initial GC run should already be kept")

	err = gc.NodeAdd(ciliumNodeEvent("172.18.0.3"))
	assert.NoError(t, err, "Handling a node event should never result in an error")
	assert.Len(t, authMap.entries, 5, "Node events should never modify the map directly")
	assert.Len(t, gc.ciliumNodesDiscovered, 4, "Discovered nodes after the sync event should be kept until the first GC run")

	err = gc.cleanupNodes(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3, "GC run after the initial sync should delete all entries which belong to deleted or non-discovered nodes")
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire})
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 1, authType: policy.AuthTypeSpire})
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 3, authType: policy.AuthTypeSpire})
	assert.Nil(t, gc.ciliumNodesDiscovered, "First GC run after the initial sync should reset the option to discover nodes")
	assert.Empty(t, gc.ciliumNodesDeleted, "GC runs should delete the successfully garbage collected entries from the list of deleted nodes")

	err = gc.NodeAdd(ciliumNodeEvent("172.18.0.5"))
	assert.NoError(t, err, "Handling a node should never result in an error")
	assert.Len(t, authMap.entries, 3, "Node should never modify the map directly")
	assert.Nil(t, gc.ciliumNodesDiscovered, "Discovered nodes after the first GC run should no longer be of any interest")

	err = gc.NodeDelete(ciliumNodeEvent("172.18.0.3"))
	assert.NoError(t, err, "Handling a node event should never result in an error")
	assert.Len(t, authMap.entries, 3, "Node events should never modify the map directly")
	assert.Len(t, gc.ciliumNodesDeleted, 1, "Deleted nodes should be kept for the next GC run")

	err = gc.cleanupNodes(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 2, "GC runs should delete all entries which belong to deleted nodes")
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire})
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 1, authType: policy.AuthTypeSpire})
	assert.Nil(t, gc.ciliumNodesDiscovered)
	assert.Empty(t, gc.ciliumNodesDeleted, "GC runs should delete the successfully garbage collected entries from the list of deleted nodes")
}

func Test_authMapGarbageCollector_cleanupPolicies(t *testing.T) {
	ctx := context.TODO()

	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 3, remoteNodeID: 0, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 4, remoteNodeID: 0, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
		},
	}
	gc := newAuthMapGC(logrus.New(), authMap, nil,
		&fakePolicyRepository{
			needsAuth: map[identity.NumericIdentity]map[identity.NumericIdentity]policy.AuthTypes{
				1: {
					2: map[policy.AuthType]struct{}{
						policy.AuthTypeSpire: {},
					},
					3: map[policy.AuthType]struct{}{
						policy.AuthTypeAlwaysFail: {},
					},
				},
			},
		},
	)

	assert.Len(t, authMap.entries, 3)

	err := gc.cleanupEntriesWithoutAuthPolicy(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 1, "GC runs should delete all entries where (the type of) auth is no longer enforced by a policy")
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire})
}

func Test_authMapGarbageCollector_cleanupExpired(t *testing.T) {
	ctx := context.TODO()

	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 1, remoteIdentity: 3, remoteNodeID: 0, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(-5 * time.Minute)},
		},
	}
	gc := newAuthMapGC(logrus.New(), authMap, nil, nil)

	assert.Len(t, authMap.entries, 2)

	err := gc.cleanupExpiredEntries(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 1, "GC runs should delete all expired entries from the map")
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire})
}

func Test_authMapGarbageCollector_cleanup(t *testing.T) {
	ctx := context.TODO()

	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire}:        {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 3, remoteIdentity: 4, remoteNodeID: 1, authType: policy.AuthTypeSpire}:        {expiration: time.Now().Add(5 * time.Minute)},  // deleted remote node
			{localIdentity: 5, remoteIdentity: 6, remoteNodeID: 0, authType: policy.AuthTypeSpire}:        {expiration: time.Now().Add(5 * time.Minute)},  // deleted remote id
			{localIdentity: 7, remoteIdentity: 8, remoteNodeID: 0, authType: policy.AuthTypeSpire}:        {expiration: time.Now().Add(5 * time.Minute)},  // deleted local id
			{localIdentity: 9, remoteIdentity: 10, remoteNodeID: 2, authType: policy.AuthTypeSpire}:       {expiration: time.Now().Add(5 * time.Minute)},  // no policy present which enforces auth between identities
			{localIdentity: 11, remoteIdentity: 12, remoteNodeID: 0, authType: policy.AuthTypeAlwaysFail}: {expiration: time.Now().Add(5 * time.Minute)},  // no policy present which enforces specific auth type
			{localIdentity: 13, remoteIdentity: 14, remoteNodeID: 0, authType: policy.AuthTypeSpire}:      {expiration: time.Now().Add(-5 * time.Minute)}, // expired
		},
	}

	gc := newAuthMapGC(logrus.New(), authMap,
		newFakeNodeIDHandler(map[uint16]string{
			1: "172.18.0.1",
			2: "172.18.0.2",
		}),
		&fakePolicyRepository{
			needsAuth: map[identity.NumericIdentity]map[identity.NumericIdentity]policy.AuthTypes{
				1: {
					2: map[policy.AuthType]struct{}{policy.AuthTypeSpire: {}},
				},
				3: {
					4: map[policy.AuthType]struct{}{policy.AuthTypeSpire: {}},
				},
				5: {
					6: map[policy.AuthType]struct{}{policy.AuthTypeSpire: {}},
				},
				7: {
					8: map[policy.AuthType]struct{}{policy.AuthTypeSpire: {}},
				},
				11: {
					12: map[policy.AuthType]struct{}{policy.AuthTypeSpire: {}},
				},
				13: {
					14: map[policy.AuthType]struct{}{policy.AuthTypeSpire: {}},
				},
			},
		},
	)

	assert.Len(t, authMap.entries, 7)

	require.NoError(t, gc.NodeAdd(ciliumNodeEvent("172.18.0.1")))
	require.NoError(t, gc.NodeAdd(ciliumNodeEvent("172.18.0.2")))
	gc.ciliumNodesSynced = true
	require.NoError(t, gc.NodeDelete(ciliumNodeEvent("172.18.0.1")))
	for i := 1; i < 15; i++ {
		require.NoError(t, gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, identity.NumericIdentity(i))))
	}
	require.NoError(t, gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeSync, 0)))
	require.NoError(t, gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeDelete, 6)))
	require.NoError(t, gc.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeDelete, 7)))

	err := gc.cleanup(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 1)
	assert.Contains(t, authMap.entries, authKey{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire})
}

func Test_authMapGarbageCollector_cleanupEndpoints(t *testing.T) {
	ctx := context.TODO()

	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire}:   {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 2, remoteIdentity: 1, remoteNodeID: 0, authType: policy.AuthTypeSpire}:   {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 3, remoteIdentity: 1, remoteNodeID: 100, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
		},
	}
	gc := newAuthMapGC(logrus.New(), authMap, nil, nil)
	gc.endpointsCache = map[uint16]*endpoint.Endpoint{
		1: {
			SecurityIdentity: &identity.Identity{
				ID: 2,
			},
		},
		2: {
			SecurityIdentity: &identity.Identity{
				ID: 3,
			},
		},
	}
	gc.endpointsCacheSynced = true

	assert.Len(t, authMap.entries, 3)

	gc.ciliumIdentitiesDiscovered = map[identity.NumericIdentity]struct{}{
		1: {},
		2: {},
		3: {},
	}
	gc.ciliumIdentitiesSynced = true

	err := gc.cleanupEndpoints(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 1, "GC runs should delete all entries where the secrity ID no longer is in the endpoint map")
	assert.Contains(t, authMap.entries, authKey{localIdentity: 3, remoteIdentity: 1, remoteNodeID: 100, authType: policy.AuthTypeSpire})
}

func Test_authMapGarbageCollector_cleanupEndpointsNoopCase(t *testing.T) {
	ctx := context.TODO()

	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: 1, remoteIdentity: 2, remoteNodeID: 0, authType: policy.AuthTypeSpire}:   {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 2, remoteIdentity: 1, remoteNodeID: 0, authType: policy.AuthTypeSpire}:   {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: 3, remoteIdentity: 1, remoteNodeID: 100, authType: policy.AuthTypeSpire}: {expiration: time.Now().Add(5 * time.Minute)},
		},
	}
	gc := newAuthMapGC(logrus.New(), authMap, nil, nil)
	gc.endpointsCache = map[uint16]*endpoint.Endpoint{
		1: {
			SecurityIdentity: &identity.Identity{
				ID: 1,
			},
		},
		2: {
			SecurityIdentity: &identity.Identity{
				ID: 2,
			},
		},
		3: {
			SecurityIdentity: &identity.Identity{
				ID: 3,
			},
		},
		4: {
			SecurityIdentity: &identity.Identity{
				ID: 3,
			},
		},
	}
	gc.endpointsCacheSynced = true

	assert.Len(t, authMap.entries, 3)

	gc.ciliumIdentitiesDiscovered = map[identity.NumericIdentity]struct{}{
		1: {},
		2: {},
		3: {},
	}
	gc.ciliumIdentitiesSynced = true

	err := gc.cleanupEndpoints(ctx)
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3, "GC runs should not have deleted entries when all secrity IDs were stil in the the endpoint map")
}

func Test_authMapGarbageCollector_HandleNodeEventError(t *testing.T) {
	authMap := &fakeAuthMap{
		entries:    map[authKey]authInfo{},
		failDelete: true,
	}
	gc := newAuthMapGC(logrus.New(), authMap, newFakeNodeIDHandler(map[uint16]string{10: "172.18.0.3"}), nil)

	event := ciliumNodeEvent("172.18.0.3")
	err := gc.NodeAdd(event)
	assert.NoError(t, err)
	err = gc.NodeDelete(event)
	assert.NoError(t, err)

	gc.ciliumNodesSynced = true
	gc.ciliumNodesDiscovered = nil
	err = gc.cleanupNodes(context.Background())
	assert.ErrorContains(t, err, "failed to cleanup deleted node: failed to delete entry")
}

func Test_authMapGarbageCollector_HandleIdentityEventError(t *testing.T) {
	authMap := &fakeAuthMap{
		entries:    map[authKey]authInfo{},
		failDelete: true,
	}
	gc := newAuthMapGC(logrus.New(), authMap, newFakeNodeIDHandler(map[uint16]string{}), nil)

	event := ciliumIdentityEvent(cache.IdentityChangeDelete, 4)
	err := gc.handleIdentityChange(context.Background(), event)
	assert.NoError(t, err)

	gc.ciliumIdentitiesSynced = true
	gc.ciliumIdentitiesDiscovered = nil
	err = gc.cleanupIdentities(context.Background())
	assert.ErrorContains(t, err, "failed to cleanup deleted identity: failed to delete entry")
}

func ciliumNodeEvent(nodeInternalIP string) nodeTypes.Node {
	return nodeTypes.Node{
		Name:    "test-node",
		Cluster: "test-cluster",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP(nodeInternalIP),
			},
		},
	}
}

func ciliumIdentityEvent(kind cache.IdentityChangeKind, id identity.NumericIdentity) cache.IdentityChange {
	return cache.IdentityChange{
		Kind: kind,
		ID:   id,
	}
}

// Fake policyRepository

type fakePolicyRepository struct {
	needsAuth map[identity.NumericIdentity]map[identity.NumericIdentity]policy.AuthTypes
}

func (r *fakePolicyRepository) GetAuthTypes(localID, remoteID identity.NumericIdentity) policy.AuthTypes {
	if remotes, localPresent := r.needsAuth[localID]; localPresent {
		if authTypes, remotePresent := remotes[remoteID]; remotePresent {
			return authTypes
		}
	}

	return nil
}
