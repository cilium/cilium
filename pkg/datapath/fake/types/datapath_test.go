// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func TestNewDatapath(t *testing.T) {
	dp := NewDatapath()
	require.NotNil(t, dp)

	require.Nil(t, dp.Node().NodeAdd(nodeTypes.Node{}))
	require.Nil(t, dp.Node().NodeUpdate(nodeTypes.Node{}, nodeTypes.Node{}))
	require.Nil(t, dp.Node().NodeDelete(nodeTypes.Node{}))
	require.Nil(t, dp.Node().NodeConfigurationChanged(datapath.LocalNodeConfiguration{}))

	require.NotNil(t, dp.LocalNodeAddressing().IPv6().Router())
	require.NotNil(t, dp.LocalNodeAddressing().IPv4().Router())
	require.NotNil(t, dp.LocalNodeAddressing().IPv4().AllocationCIDR())
}
