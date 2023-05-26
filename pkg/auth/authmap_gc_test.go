// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/identity"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/policy"
)

func Test_authMapGarbageCollector_initialSync(t *testing.T) {
	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: identity.NumericIdentity(1), remoteIdentity: identity.NumericIdentity(2), remoteNodeID: 10, authType: policy.AuthTypeDisabled}:  {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(4), remoteNodeID: 0, authType: policy.AuthTypeDisabled}:   {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: identity.NumericIdentity(10), remoteIdentity: identity.NumericIdentity(11), remoteNodeID: 0, authType: policy.AuthTypeDisabled}: {expiration: time.Now().Add(5 * time.Minute)},
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(3), remoteNodeID: 11, authType: policy.AuthTypeDisabled}:  {expiration: time.Now().Add(-5 * time.Minute)},
		},
	}
	am := newAuthMapGC(authMap,
		newFakeIPCache(map[uint16]string{
			10: "172.18.0.3",
		}),
	)

	err := am.handleCiliumNodeEvent(context.Background(), ciliumNodeEvent(resource.Upsert, "172.18.0.3"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 4) // no modification at upsert

	err = am.handleCiliumNodeEvent(context.Background(), ciliumNodeEvent(resource.Sync, ""))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3) // deleted all entries where remote node id doesn't match existing (10) or local node (0)

	err = am.handleCiliumIdentityEvent(context.Background(), ciliumIdentityEvent(resource.Upsert, "11"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3) // no modification at upsert

	err = am.handleCiliumIdentityEvent(context.Background(), ciliumIdentityEvent(resource.Upsert, "10"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3) // no modification at upsert

	err = am.handleCiliumIdentityEvent(context.Background(), ciliumIdentityEvent(resource.Sync, ""))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 1) // deleted all entries where local and remote identity are no longer existing
}

func Test_authMapGarbageCollector_gc(t *testing.T) {
	authMap := &fakeAuthMap{
		entries: map[authKey]authInfo{
			{localIdentity: identity.NumericIdentity(1), remoteIdentity: identity.NumericIdentity(2), remoteNodeID: 10, authType: policy.AuthTypeDisabled}:  {expiration: time.Now().Add(5 * time.Minute)},  // deleted remote node
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(4), remoteNodeID: 0, authType: policy.AuthTypeDisabled}:   {expiration: time.Now().Add(5 * time.Minute)},  // deleted remote id
			{localIdentity: identity.NumericIdentity(10), remoteIdentity: identity.NumericIdentity(11), remoteNodeID: 0, authType: policy.AuthTypeDisabled}: {expiration: time.Now().Add(5 * time.Minute)},  // deleted local id
			{localIdentity: identity.NumericIdentity(2), remoteIdentity: identity.NumericIdentity(3), remoteNodeID: 11, authType: policy.AuthTypeDisabled}:  {expiration: time.Now().Add(-5 * time.Minute)}, // expired
		},
	}
	am := authMapGarbageCollector{
		authmap: authMap,
		ipCache: newFakeIPCache(map[uint16]string{
			10: "172.18.0.3",
		}),
	}

	assert.Len(t, authMap.entries, 4)

	err := am.handleCiliumNodeEvent(context.Background(), ciliumNodeEvent(resource.Delete, "172.18.0.3"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 3)

	err = am.handleCiliumIdentityEvent(context.Background(), ciliumIdentityEvent(resource.Delete, "4"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 2)

	err = am.handleCiliumIdentityEvent(context.Background(), ciliumIdentityEvent(resource.Delete, "10"))
	assert.NoError(t, err)
	assert.Len(t, authMap.entries, 1)

	err = am.CleanupExpiredEntries(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, authMap.entries)
}

func Test_authMapGarbageCollector_HandleNodeEventError(t *testing.T) {
	authMap := &fakeAuthMap{
		entries:    map[authKey]authInfo{},
		failDelete: true,
	}
	am := authMapGarbageCollector{
		authmap: authMap,
		ipCache: newFakeIPCache(map[uint16]string{}),
	}

	event := ciliumNodeEvent(resource.Delete, "172.18.0.3")
	var eventErr error
	event.Done = func(err error) {
		eventErr = err
	}
	err := am.handleCiliumNodeEvent(context.Background(), event)
	assert.ErrorContains(t, err, "failed to cleanup deleted node: failed to delete entry")
	assert.ErrorContains(t, eventErr, "failed to cleanup deleted node: failed to delete entry")
}

func Test_authMapGarbageCollector_HandleIdentityEventError(t *testing.T) {
	authMap := &fakeAuthMap{
		entries:    map[authKey]authInfo{},
		failDelete: true,
	}
	am := authMapGarbageCollector{
		authmap: authMap,
		ipCache: newFakeIPCache(map[uint16]string{}),
	}

	event := ciliumIdentityEvent(resource.Delete, "4")
	var eventErr error
	event.Done = func(err error) {
		eventErr = err
	}
	err := am.handleCiliumIdentityEvent(context.Background(), event)
	assert.ErrorContains(t, err, "failed to cleanup deleted identity: failed to delete entry")
	assert.ErrorContains(t, eventErr, "failed to cleanup deleted identity: failed to delete entry")
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

func ciliumIdentityEvent(eventType resource.EventKind, id string) resource.Event[*ciliumv2.CiliumIdentity] {
	return resource.Event[*ciliumv2.CiliumIdentity]{
		Kind: eventType,
		Done: func(err error) {},
		Object: &ciliumv2.CiliumIdentity{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-ns",
				Name:      id,
			},
		},
		Key: resource.Key{Namespace: "test-ns", Name: id},
	}
}
