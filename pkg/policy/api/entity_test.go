// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	k8sapi "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

// matches returns true if the entity matches the labels
func (e Entity) matches(ctx labels.LabelArray) bool {
	return EntitySlice{e}.matches(ctx)
}

// matches returns true if any of the entities in the slice match the labels
func (s EntitySlice) matches(ctx labels.LabelArray) bool {
	return s.GetAsEndpointSelectors().Matches(ctx)
}

func TestEntityMatches(t *testing.T) {
	InitEntities("cluster1")

	require.True(t, EntityHost.matches(labels.ParseLabelArray("reserved:host")))
	require.True(t, EntityHost.matches(labels.ParseLabelArray("reserved:host", "id:foo")))
	require.False(t, EntityHost.matches(labels.ParseLabelArray("reserved:world")))
	require.False(t, EntityHost.matches(labels.ParseLabelArray("reserved:health")))
	require.False(t, EntityHost.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.False(t, EntityHost.matches(labels.ParseLabelArray("reserved:none")))
	require.False(t, EntityHost.matches(labels.ParseLabelArray("id=foo")))

	require.True(t, EntityAll.matches(labels.ParseLabelArray("reserved:host")))
	require.True(t, EntityAll.matches(labels.ParseLabelArray("reserved:world")))
	require.True(t, EntityAll.matches(labels.ParseLabelArray("reserved:health")))
	require.True(t, EntityAll.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.True(t, EntityAll.matches(labels.ParseLabelArray("reserved:none"))) // in a white-list model, All trumps None
	require.True(t, EntityAll.matches(labels.ParseLabelArray("id=foo")))

	require.True(t, EntityCluster.matches(labels.ParseLabelArray("reserved:host")))
	require.True(t, EntityCluster.matches(labels.ParseLabelArray("reserved:init")))
	require.True(t, EntityCluster.matches(labels.ParseLabelArray("reserved:health")))
	require.True(t, EntityCluster.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.False(t, EntityCluster.matches(labels.ParseLabelArray("reserved:world")))
	require.False(t, EntityCluster.matches(labels.ParseLabelArray("reserved:none")))

	clusterLabel := fmt.Sprintf("k8s:%s=%s", k8sapi.PolicyLabelCluster, "cluster1")
	require.True(t, EntityCluster.matches(labels.ParseLabelArray(clusterLabel, "id=foo")))
	require.True(t, EntityCluster.matches(labels.ParseLabelArray(clusterLabel, "id=foo", "id=bar")))
	require.False(t, EntityCluster.matches(labels.ParseLabelArray("id=foo")))

	require.False(t, EntityWorld.matches(labels.ParseLabelArray("reserved:host")))
	require.True(t, EntityWorld.matches(labels.ParseLabelArray("reserved:world")))
	require.False(t, EntityWorld.matches(labels.ParseLabelArray("reserved:health")))
	require.False(t, EntityWorld.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.False(t, EntityWorld.matches(labels.ParseLabelArray("reserved:none")))
	require.False(t, EntityWorld.matches(labels.ParseLabelArray("id=foo")))
	require.False(t, EntityWorld.matches(labels.ParseLabelArray("id=foo", "id=bar")))

	require.False(t, EntityNone.matches(labels.ParseLabelArray("reserved:host")))
	require.False(t, EntityNone.matches(labels.ParseLabelArray("reserved:world")))
	require.False(t, EntityNone.matches(labels.ParseLabelArray("reserved:health")))
	require.False(t, EntityNone.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.False(t, EntityNone.matches(labels.ParseLabelArray("reserved:init")))
	require.False(t, EntityNone.matches(labels.ParseLabelArray("id=foo")))
	require.False(t, EntityNone.matches(labels.ParseLabelArray(clusterLabel, "id=foo", "id=bar")))

}

func TestEntitySliceMatches(t *testing.T) {
	InitEntities("cluster1")

	slice := EntitySlice{EntityHost, EntityWorld}
	require.True(t, slice.matches(labels.ParseLabelArray("reserved:host")))
	require.True(t, slice.matches(labels.ParseLabelArray("reserved:world")))
	require.False(t, slice.matches(labels.ParseLabelArray("reserved:health")))
	require.False(t, slice.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.False(t, slice.matches(labels.ParseLabelArray("reserved:none")))
	require.False(t, slice.matches(labels.ParseLabelArray("id=foo")))

	slice = EntitySlice{EntityHost, EntityHealth}
	require.True(t, slice.matches(labels.ParseLabelArray("reserved:host")))
	require.False(t, slice.matches(labels.ParseLabelArray("reserved:world")))
	require.True(t, slice.matches(labels.ParseLabelArray("reserved:health")))
	require.False(t, slice.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.False(t, slice.matches(labels.ParseLabelArray("reserved:none")))
	require.False(t, slice.matches(labels.ParseLabelArray("id=foo")))
}
