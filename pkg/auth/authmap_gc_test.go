// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/policy"
)

func Test_authMapGarbageCollector_initialSync(t *testing.T) {
	ctx := context.TODO()

	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: identity.NumericIdentity(1), remoteIdentity: identity.NumericIdentity(2), remoteNodeID: 10, authType: policy.AuthTypeDisabled}:  {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(4), remoteNodeID: 0, authType: policy.AuthTypeDisabled}:   {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: identity.NumericIdentity(10), remoteIdentity: identity.NumericIdentity(11), remoteNodeID: 0, authType: policy.AuthTypeDisabled}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(3), remoteNodeID: 11, authType: policy.AuthTypeDisabled}:  {expiration: time.Now().Add(-5 * time.Minute)},
		},
	}
	am := newAuthMapGC(logrus.New(), authMap, newFakeIPCache(map[uint16]string{
		9:  "172.18.0.2",
		10: "172.18.0.3",
		11: "172.18.0.4",
	}), nil)

	assert.Len(t, am.ciliumNodesDiscovered, 1) // local node 0
	assert.Empty(t, am.ciliumIdentitiesDiscovered)
	assert.False(t, am.ciliumIdentitiesSynced)

	err := am.handleCiliumNodeEvent(ctx, ciliumNodeEvent(resource.Upsert, "172.18.0.3"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.Len(t, am.ciliumNodesDiscovered, 2)

	err = am.handleCiliumNodeEvent(ctx, ciliumNodeEvent(resource.Sync, ""))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.Len(t, am.ciliumNodesDiscovered, 2)
	assert.True(t, am.ciliumNodesSynced)

	err = am.handleCiliumNodeEvent(ctx, ciliumNodeEvent(resource.Upsert, "172.18.0.2"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.Len(t, am.ciliumNodesDiscovered, 3) // Keep collecting upserts until reset

	am.ciliumNodesDiscovered = nil // Reset

	err = am.handleCiliumNodeEvent(ctx, ciliumNodeEvent(resource.Upsert, "172.18.0.4"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.Nil(t, am.ciliumNodesDiscovered)

	err = am.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, 11))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.Len(t, am.ciliumIdentitiesDiscovered, 1)

	err = am.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, 10))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.Len(t, am.ciliumIdentitiesDiscovered, 2)

	err = am.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeSync, 0))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.True(t, am.ciliumIdentitiesSynced)

	err = am.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, 12))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.Len(t, am.ciliumIdentitiesDiscovered, 3) // Keep collecting upserts until reset

	am.ciliumIdentitiesDiscovered = nil // Reset

	err = am.handleIdentityChange(ctx, ciliumIdentityEvent(cache.IdentityChangeUpsert, 13))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4)
	assert.Nil(t, am.ciliumIdentitiesDiscovered)
}

func Test_authMapGarbageCollector_gc(t *testing.T) {
	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: identity.NumericIdentity(100), remoteIdentity: identity.NumericIdentity(111), remoteNodeID: 10, authType: policy.AuthTypeSpire}:  {expiration: time.Now().Add(5 * time.Minute)},  // deleted remote node
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(4), remoteNodeID: 0, authType: policy.AuthTypeSpire}:       {expiration: time.Now().Add(5 * time.Minute)},  // deleted remote id
			{localIdentity: identity.NumericIdentity(10), remoteIdentity: identity.NumericIdentity(11), remoteNodeID: 0, authType: policy.AuthTypeSpire}:     {expiration: time.Now().Add(5 * time.Minute)},  // deleted local id
			{localIdentity: identity.NumericIdentity(5), remoteIdentity: identity.NumericIdentity(6), remoteNodeID: 12, authType: policy.AuthTypeSpire}:      {expiration: time.Now().Add(5 * time.Minute)},  // no policy present which enforces auth between identities
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(3), remoteNodeID: 12, authType: policy.AuthTypeAlwaysFail}: {expiration: time.Now().Add(5 * time.Minute)},  // no policy present which enforces specific auth type
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(3), remoteNodeID: 11, authType: policy.AuthTypeSpire}:      {expiration: time.Now().Add(-5 * time.Minute)}, // expired
		},
	}

	gc := newAuthMapGC(logrus.New(), authMap,
		newFakeIPCache(map[uint16]string{
			10: "172.18.0.3",
		}),
		&fakePolicyRepository{
			needsAuth: map[identity.NumericIdentity]map[identity.NumericIdentity]policy.AuthTypes{
				identity.NumericIdentity(1): {
					identity.NumericIdentity(2): map[policy.AuthType]struct{}{
						policy.AuthTypeSpire: {},
					},
				},
				identity.NumericIdentity(2): {
					identity.NumericIdentity(3): map[policy.AuthType]struct{}{
						policy.AuthTypeSpire: {},
					},
					identity.NumericIdentity(4): map[policy.AuthType]struct{}{
						policy.AuthTypeSpire: {},
					},
				},
				identity.NumericIdentity(10): {
					identity.NumericIdentity(11): map[policy.AuthType]struct{}{
						policy.AuthTypeSpire: {},
					},
				},
				identity.NumericIdentity(100): {
					identity.NumericIdentity(111): map[policy.AuthType]struct{}{
						policy.AuthTypeSpire: {},
					},
				},
			},
		},
	)

	assert.Len(t, authMap.entries, 6)

	err := gc.cleanupExpiredEntries(context.Background())
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 5)

	err = gc.cleanupEntriesWithoutAuthPolicy(context.Background())
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3)

	err = gc.handleCiliumNodeEvent(context.Background(), ciliumNodeEvent(resource.Delete, "172.18.0.3"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3)

	err = gc.handleIdentityChange(context.Background(), ciliumIdentityEvent(cache.IdentityChangeDelete, 4))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3)
	assert.Len(t, gc.ciliumIdentitiesDeleted, 1)

	err = gc.handleIdentityChange(context.Background(), ciliumIdentityEvent(cache.IdentityChangeDelete, 10))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3)
	assert.Len(t, gc.ciliumIdentitiesDeleted, 2)

	gc.ciliumIdentitiesSynced = true
	err = gc.cleanupIdentities(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, authMap.entries)
	assert.Empty(t, gc.ciliumIdentitiesDeleted)

	gc.ciliumNodesSynced = true
	err = gc.cleanupNodes(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, authMap.entries)
	assert.Empty(t, gc.ciliumNodesDeleted)
}

func Test_authMapGarbageCollector_HandleNodeEventError(t *testing.T) {
	authMap := &fakeAuthMap{
		entries:    map[authKey]authInfo{},
		failDelete: true,
	}
	gc := newAuthMapGC(logrus.New(), authMap, newFakeIPCache(map[uint16]string{10: "172.18.0.3"}), nil)

	event := ciliumNodeEvent(resource.Delete, "172.18.0.3")
	var eventErr error
	event.Done = func(err error) {
		eventErr = err
	}
	err := gc.handleCiliumNodeEvent(context.Background(), event)
	assert.NoError(t, err)
	assert.NoError(t, eventErr)

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
	gc := newAuthMapGC(logrus.New(), authMap, newFakeIPCache(map[uint16]string{}), nil)

	event := ciliumIdentityEvent(cache.IdentityChangeDelete, 4)
	err := gc.handleIdentityChange(context.Background(), event)
	assert.NoError(t, err)

	gc.ciliumIdentitiesSynced = true
	gc.ciliumIdentitiesDiscovered = nil
	err = gc.cleanupIdentities(context.Background())
	assert.ErrorContains(t, err, "failed to cleanup deleted identity: failed to delete entry")
}

func ciliumNodeEvent(eventType resource.EventKind, nodeInternalIP string) resource.Event[*ciliumv2.CiliumNode] {
	return resource.Event[*ciliumv2.CiliumNode]{
		Kind: eventType,
		Done: func(err error) {},
		Object: &ciliumv2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-ns",
				Name:      "test-node",
			},
			Spec: ciliumv2.NodeSpec{
				Addresses: []ciliumv2.NodeAddress{
					{
						Type: addressing.NodeInternalIP,
						IP:   nodeInternalIP,
					},
				},
			},
		},
		Key: resource.Key{Namespace: "test-ns", Name: "test-node"},
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
