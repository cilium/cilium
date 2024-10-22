// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package syncstate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestSyncState(t *testing.T) {
	var doneFuncs []func(context.Context)
	ss := new(MetricsProvider(), types.ClusterInfo{Name: "test"})

	// add several resource to the SyncState
	for i := 0; i < 3; i++ {
		doneFuncs = append(doneFuncs, ss.WaitForResource())
	}
	ss.Stop()

	// call all doneFuncs to simulate the resources being synchronized
	for _, f := range doneFuncs {
		// ensure that SyncState is not complete until all doneFuncs are called
		require.False(t, ss.Complete())
		f(context.Background())
	}

	require.True(t, ss.Complete())
}
