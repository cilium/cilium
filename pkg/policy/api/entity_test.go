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

	require.Equal(t, true, EntityHost.matches(labels.ParseLabelArray("reserved:host")))
	require.Equal(t, true, EntityHost.matches(labels.ParseLabelArray("reserved:host", "id:foo")))
	require.Equal(t, false, EntityHost.matches(labels.ParseLabelArray("reserved:world")))
	require.Equal(t, false, EntityHost.matches(labels.ParseLabelArray("reserved:health")))
	require.Equal(t, false, EntityHost.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.Equal(t, false, EntityHost.matches(labels.ParseLabelArray("reserved:none")))
	require.Equal(t, false, EntityHost.matches(labels.ParseLabelArray("id=foo")))

	require.Equal(t, true, EntityAll.matches(labels.ParseLabelArray("reserved:host")))
	require.Equal(t, true, EntityAll.matches(labels.ParseLabelArray("reserved:world")))
	require.Equal(t, true, EntityAll.matches(labels.ParseLabelArray("reserved:health")))
	require.Equal(t, true, EntityAll.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.Equal(t, true, EntityAll.matches(labels.ParseLabelArray("reserved:none"))) // in a white-list model, All trumps None
	require.Equal(t, true, EntityAll.matches(labels.ParseLabelArray("id=foo")))

	require.Equal(t, true, EntityCluster.matches(labels.ParseLabelArray("reserved:host")))
	require.Equal(t, true, EntityCluster.matches(labels.ParseLabelArray("reserved:init")))
	require.Equal(t, true, EntityCluster.matches(labels.ParseLabelArray("reserved:health")))
	require.Equal(t, true, EntityCluster.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.Equal(t, false, EntityCluster.matches(labels.ParseLabelArray("reserved:world")))
	require.Equal(t, false, EntityCluster.matches(labels.ParseLabelArray("reserved:none")))

	clusterLabel := fmt.Sprintf("k8s:%s=%s", k8sapi.PolicyLabelCluster, "cluster1")
	require.Equal(t, true, EntityCluster.matches(labels.ParseLabelArray(clusterLabel, "id=foo")))
	require.Equal(t, true, EntityCluster.matches(labels.ParseLabelArray(clusterLabel, "id=foo", "id=bar")))
	require.Equal(t, false, EntityCluster.matches(labels.ParseLabelArray("id=foo")))

	require.Equal(t, false, EntityWorld.matches(labels.ParseLabelArray("reserved:host")))
	require.Equal(t, true, EntityWorld.matches(labels.ParseLabelArray("reserved:world")))
	require.Equal(t, false, EntityWorld.matches(labels.ParseLabelArray("reserved:health")))
	require.Equal(t, false, EntityWorld.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.Equal(t, false, EntityWorld.matches(labels.ParseLabelArray("reserved:none")))
	require.Equal(t, false, EntityWorld.matches(labels.ParseLabelArray("id=foo")))
	require.Equal(t, false, EntityWorld.matches(labels.ParseLabelArray("id=foo", "id=bar")))

	require.Equal(t, false, EntityNone.matches(labels.ParseLabelArray("reserved:host")))
	require.Equal(t, false, EntityNone.matches(labels.ParseLabelArray("reserved:world")))
	require.Equal(t, false, EntityNone.matches(labels.ParseLabelArray("reserved:health")))
	require.Equal(t, false, EntityNone.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.Equal(t, false, EntityNone.matches(labels.ParseLabelArray("reserved:init")))
	require.Equal(t, false, EntityNone.matches(labels.ParseLabelArray("id=foo")))
	require.Equal(t, false, EntityNone.matches(labels.ParseLabelArray(clusterLabel, "id=foo", "id=bar")))

}

func TestEntitySliceMatches(t *testing.T) {
	InitEntities("cluster1")

	slice := EntitySlice{EntityHost, EntityWorld}
	require.Equal(t, true, slice.matches(labels.ParseLabelArray("reserved:host")))
	require.Equal(t, true, slice.matches(labels.ParseLabelArray("reserved:world")))
	require.Equal(t, false, slice.matches(labels.ParseLabelArray("reserved:health")))
	require.Equal(t, false, slice.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.Equal(t, false, slice.matches(labels.ParseLabelArray("reserved:none")))
	require.Equal(t, false, slice.matches(labels.ParseLabelArray("id=foo")))

	slice = EntitySlice{EntityHost, EntityHealth}
	require.Equal(t, true, slice.matches(labels.ParseLabelArray("reserved:host")))
	require.Equal(t, false, slice.matches(labels.ParseLabelArray("reserved:world")))
	require.Equal(t, true, slice.matches(labels.ParseLabelArray("reserved:health")))
	require.Equal(t, false, slice.matches(labels.ParseLabelArray("reserved:unmanaged")))
	require.Equal(t, false, slice.matches(labels.ParseLabelArray("reserved:none")))
	require.Equal(t, false, slice.matches(labels.ParseLabelArray("id=foo")))
}
