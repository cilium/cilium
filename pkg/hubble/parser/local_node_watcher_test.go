// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package parser

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

func Test_LocalNodeWatcher(t *testing.T) {
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

	store := node.NewTestLocalNodeStore(localNode)

	// Start the watcher with a cancellable context.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	watcher := &LocalNodeWatcher{}
	runDone := make(chan error, 1)
	go func() {
		runDone <- watcher.Run(ctx, store)
	}()

	t.Run("NodeLabels", func(t *testing.T) {
		require.EventuallyWithT(
			t,
			func(c *assert.CollectT) {
				assert.Equal(c, localNodeLabelSlice, watcher.NodeLabels())
				assert.Equal(c, localNode.Fullname(), watcher.NodeName())
			},
			10*time.Second,
			10*time.Millisecond,
		)
	})

	t.Run("update", func(t *testing.T) {
		store.Update(func(ln *node.LocalNode) {
			*ln = updatedNode
		})
		require.EventuallyWithT(
			t,
			func(c *assert.CollectT) {
				assert.Equal(c, updatedNodeLabelSlice, watcher.NodeLabels(), "node labels mismatch")
				assert.Equal(c, updatedNode.Fullname(), watcher.NodeName(), "node name mismatch")
			},
			10*time.Second,
			10*time.Millisecond,
		)
	})

	t.Run("context_cancellation", func(t *testing.T) {
		cancel()
		err := <-runDone
		require.NoError(t, err)
		// After cancellation, cache should be cleared by complete().
		require.EventuallyWithT(
			t,
			func(c *assert.CollectT) {
				assert.Empty(c, watcher.NodeLabels())
				assert.Empty(c, watcher.NodeName())
			},
			10*time.Second,
			10*time.Millisecond,
		)
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
