// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClusterIDsManagerProvisioner(t *testing.T) {
	mgr := idsMgrProvider(idsMgrProviderParams{})
	require.NotNil(t, mgr, "A non-nil instance of the default implementation should be returned")
	require.NoError(t, mgr.ReserveClusterID(10), "Reserving a cluster ID should succeed")

	mgr2 := idsMgrProvider(idsMgrProviderParams{Manager: mgr})
	require.Equal(t, mgr, mgr2, "The specified implementation should be propagated")
	require.NoError(t, mgr.ReserveClusterID(11), "Reserving a cluster ID should succeed")
}

func TestClusterMeshUsedIDs(t *testing.T) {
	mgr := NewClusterMeshUsedIDs()

	require.NoError(t, mgr.ReserveClusterID(10), "Reserving a cluster ID should succeed")
	require.NoError(t, mgr.ReserveClusterID(250), "Reserving another cluster ID should succeed")
	require.Error(t, mgr.ReserveClusterID(250), "Attempting to reserve again the same cluster ID should fail")

	mgr.ReleaseClusterID(250)
	require.NoError(t, mgr.ReserveClusterID(55), "Reserving a released cluster ID should succeed")
}
