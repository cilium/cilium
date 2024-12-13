// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func TestNewNodeHandler(t *testing.T) {
	nh := NewNodeHandler()
	require.NotNil(t, nh)

	require.NoError(t, nh.NodeAdd(nodeTypes.Node{}))
	require.NoError(t, nh.NodeUpdate(nodeTypes.Node{}, nodeTypes.Node{}))
	require.NoError(t, nh.NodeDelete(nodeTypes.Node{}))
	require.NoError(t, nh.NodeConfigurationChanged(datapath.LocalNodeConfiguration{}))
}
