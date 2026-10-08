// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestClusterIDsManager(t *testing.T) {
	const localClusterID = 1
	mgr := NewClusterIDsManager(types.ClusterInfo{ID: localClusterID})

	require.NoError(t, mgr.ReserveClusterID(10), "Reserving a cluster ID should succeed")
	require.NoError(t, mgr.ReserveClusterID(250), "Reserving another cluster ID should succeed")
	require.Error(t, mgr.ReserveClusterID(250), "Attempting to reserve again the same cluster ID should fail")

	mgr.ReleaseClusterID(250)
	require.NoError(t, mgr.ReserveClusterID(250), "Reserving a released cluster ID should succeed")

	require.Error(t, mgr.ReserveClusterID(types.ClusterIDUnset), "Reserving ClusterID 0 should fail")
	mgr.ReleaseClusterID(types.ClusterIDUnset)
	require.Error(t, mgr.ReserveClusterID(types.ClusterIDUnset), "Releasing ClusterID 0 should be a no-op")

	require.Error(t, mgr.ReserveClusterID(localClusterID), "Reserving the local ClusterID should fail")
}
