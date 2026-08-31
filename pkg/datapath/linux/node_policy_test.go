// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func TestNodePolicy(t *testing.T) {
	n := &nodeTypes.Node{Name: "node-1"}
	lifecycle := &cell.DefaultLifecycle{}
	p := NewNodePolicy(lifecycle)

	require.False(t, p.EnableEncapsulation(n, false))
	require.True(t, p.EnableEncapsulation(n, true))

	called := false
	p.SetEnableEncapsulation(func(got *nodeTypes.Node) bool {
		called = true
		require.Same(t, n, got)
		return true
	})
	require.True(t, p.EnableEncapsulation(n, false))
	require.True(t, called)

	require.NoError(t, lifecycle.Start(hivetest.Logger(t), t.Context()))
	require.Panics(t, func() {
		p.SetEnableEncapsulation(func(*nodeTypes.Node) bool { return false })
	})
}
