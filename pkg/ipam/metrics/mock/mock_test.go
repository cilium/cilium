// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMock(t *testing.T) {
	api := NewMockMetrics()
	api.AllocationAttempt("createInterfaceAndAllocateIP", "foo", "s-1", 0)
	require.Equal(t, int64(1), api.GetAllocationAttempts("createInterfaceAndAllocateIP", "foo", "s-1"))
	api.AddIPAllocation("s-1", 10)
	api.AddIPAllocation("s-1", 20)
	require.Equal(t, int64(30), api.IPAllocations("s-1"))
	api.SetAllocatedIPs("used", 200)
	require.Equal(t, 200, api.AllocatedIPs("used"))
	api.SetAvailableInterfaces(10)
	require.Equal(t, 10, api.AvailableInterfaces())
	api.SetInterfaceCandidates(10)
	require.Equal(t, 10, api.InterfaceCandidates())
	api.SetEmptyInterfaceSlots(10)
	require.Equal(t, 10, api.EmptyInterfaceSlots())
	api.SetNodes("at-capacity", 5)
	require.Equal(t, 5, api.Nodes("at-capacity"))
	api.IncResyncCount()
	require.Equal(t, int64(1), api.ResyncCount())
}
