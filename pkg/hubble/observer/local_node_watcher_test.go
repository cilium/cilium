// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

func Test_LocalNodeWatcher(t *testing.T) {
	ctx := t.Context()

	localNode := node.LocalNode{
		Node: types.Node{
			Name: "ip-1-2-3-4.us-west-2.compute.internal",
			Labels: map[string]string{
				"kubernetes.io/arch":            "amd64",
				"kubernetes.io/os":              "linux",
				"kubernetes.io/hostname":        "ip-1-2-3-4.us-west-2.compute.internal",
				"topology.kubernetes.io/region": "us-west-2",
				"topology.kubernetes.io/zone":   "us-west-2d",
			},
		},
		Local: &node.LocalNodeInfo{},
	}
	localNodeLabelSlice := []string{
		"kubernetes.io/arch=amd64",
		"kubernetes.io/hostname=ip-1-2-3-4.us-west-2.compute.internal",
		"kubernetes.io/os=linux",
		"topology.kubernetes.io/region=us-west-2",
		"topology.kubernetes.io/zone=us-west-2d",
	}
	updatedNode := node.LocalNode{
		Node: types.Node{
			Name: "kind-kind",
			Labels: map[string]string{
				"kubernetes.io/arch":     "arm64",
				"kubernetes.io/os":       "linux",
				"kubernetes.io/hostname": "kind-kind",
			},
		},
		Local: &node.LocalNodeInfo{},
	}
	updatedNodeLabelSlice := []string{
		"kubernetes.io/arch=arm64",
		"kubernetes.io/hostname=kind-kind",
		"kubernetes.io/os=linux",
	}

	var watcher *LocalNodeWatcher
	store := node.NewTestLocalNodeStore(localNode)

	t.Run("NewLocalNodeWatcher", func(t *testing.T) {
		var err error
		watcher, err = NewLocalNodeWatcher(ctx, store)
		require.NoError(t, err)
		require.NotNil(t, watcher)
	})

	t.Run("OnDecodedFlow", func(t *testing.T) {
		var flow flowpb.Flow
		stop, err := watcher.OnDecodedFlow(ctx, &flow)
		require.False(t, stop)
		require.NoError(t, err)
		require.Equal(t, localNodeLabelSlice, flow.GetNodeLabels())
	})

	t.Run("update", func(t *testing.T) {
		store.Update(func(ln *node.LocalNode) {
			*ln = updatedNode
		})
		require.EventuallyWithT(
			t,
			func(c *assert.CollectT) {
				var flow flowpb.Flow
				stop, err := watcher.OnDecodedFlow(ctx, &flow)
				if assert.False(c, stop) {
					assert.NoError(c, err)
					assert.Equal(c, updatedNodeLabelSlice, flow.GetNodeLabels(), "node labels mismatch")
				}
			},
			10*time.Second,
			10*time.Millisecond,
		)
	})

	t.Run("complete", func(t *testing.T) {
		watcher.complete(nil)
		var flow flowpb.Flow
		stop, err := watcher.OnDecodedFlow(ctx, &flow)
		require.False(t, stop)
		require.NoError(t, err)
		require.Empty(t, flow.GetNodeLabels())
	})
}

func Test_sortedLabelSlice(t *testing.T) {
	tt := []struct {
		name  string
		input map[string]string
		want  []string
	}{
		{
			name:  "nil",
			input: nil,
			want:  []string{},
		},
		{
			name:  "empty",
			input: map[string]string{},
			want:  []string{},
		},
		{
			name: "key=val",
			input: map[string]string{
				"key": "val",
			},
			want: []string{"key=val"},
		},
		{
			name: "ordering",
			input: map[string]string{
				"b": "foo",
				"a": "bar",
				"c": "qux",
			},
			want: []string{"a=bar", "b=foo", "c=qux"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, sortedLabelSlice(tc.input))
		})
	}
}
