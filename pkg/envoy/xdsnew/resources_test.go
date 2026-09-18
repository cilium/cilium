// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"testing"

	"github.com/stretchr/testify/require"

	cilium "github.com/cilium/proxy/go/cilium/api"

	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func TestPreparedResourceChangesKeepSinglePolicyInline(t *testing.T) {
	state := &nodeState{}
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	var changes resourceChanges
	require.True(t, snapshotTypesChangedBy(changes.typeURLs()).Empty(), "no changes must not invalidate unrelated resource types")
	changes.add(typeurl.NetworkPolicy, "policy", resourceEntry{}, resourceEntry{resource: policy, revision: callbacks.Generation(1).Revision(), transaction: callbacks.Generation(1).TransactionID()})
	types, inverse := changes.typeURLs(), changes.inverse()
	require.Equal(t, typeurl.NewSet(typeurl.NetworkPolicy), types)
	require.Equal(t, "policy", changes.first.name)
	require.Equal(t, typeurl.NetworkPolicy, changes.first.typeURL)
	require.Same(t, policy, changes.first.next.resource)
	require.Equal(t, callbacks.Generation(1).Revision(), changes.first.next.revision)
	require.Equal(t, callbacks.Generation(1).TransactionID(), changes.first.next.transaction)
	require.Nil(t, changes.first.previous.resource)
	require.Empty(t, changes.more)
	require.True(t, inverse.hasSingleton())

	state.commitResourceMutation(changes, 1)
	changes = resourceChanges{}
	changes.add(typeurl.NetworkPolicy, "policy", state.resourceEntries(typeurl.NetworkPolicy)["policy"], resourceEntry{revision: callbacks.Generation(2).Revision(), transaction: callbacks.Generation(2).TransactionID()})
	types, inverse = changes.typeURLs(), changes.inverse()
	require.Equal(t, typeurl.NewSet(typeurl.NetworkPolicy), types)
	require.Equal(t, "policy", changes.first.name)
	require.Nil(t, changes.first.next.resource)
	require.Equal(t, callbacks.Generation(2).Revision(), changes.first.next.revision)
	require.Equal(t, callbacks.Generation(2).TransactionID(), changes.first.next.transaction)
	require.Same(t, policy, changes.first.previous.resource)
	require.Empty(t, changes.more)
	require.True(t, inverse.hasSingleton())
	require.Equal(t, callbacks.Generation(1).Revision(), changes.first.previous.revision)
}

func TestSnapshotTypesChangedBy(t *testing.T) {
	for _, test := range []struct {
		name    string
		changed typeurl.Set
		want    typeurl.Set
	}{
		{"zero", typeurl.Set{}, typeurl.Set{}},
		{"initialized empty", typeurl.NewSet(), typeurl.NewSet()},
		{"policy", typeurl.NewSet(typeurl.NetworkPolicy), typeurl.NewSet(typeurl.NetworkPolicy)},
		{"listener", typeurl.NewSet(typeurl.Listener), typeurl.NewSet(typeurl.Listener)},
		{"cluster", typeurl.NewSet(typeurl.Cluster), typeurl.NewSet(typeurl.Cluster, typeurl.Endpoint)},
		{"listener and cluster", typeurl.NewSet(typeurl.Listener, typeurl.Cluster), typeurl.NewSet(typeurl.Listener, typeurl.Cluster, typeurl.Endpoint)},
		{"all", typeurl.All(), typeurl.All()},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, snapshotTypesChangedBy(test.changed))
		})
	}
}
