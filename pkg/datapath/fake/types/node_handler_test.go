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

	require.Nil(t, nh.NodeAdd(nodeTypes.Node{}))
	require.Nil(t, nh.NodeUpdate(nodeTypes.Node{}, nodeTypes.Node{}))
	require.Nil(t, nh.NodeDelete(nodeTypes.Node{}))
	require.Nil(t, nh.NodeConfigurationChanged(datapath.LocalNodeConfiguration{}))
}
