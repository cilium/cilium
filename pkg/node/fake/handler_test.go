// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node/types"
)

func TestNewNodeHandler(t *testing.T) {
	nh := NewHandler()
	require.NotNil(t, nh)

	require.NoError(t, nh.NodeAdd(types.Node{}))
	require.NoError(t, nh.NodeUpdate(types.Node{}, types.Node{}))
	require.NoError(t, nh.NodeDelete(types.Node{}))
}
