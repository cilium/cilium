// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"
)

func TestEndpointTransformPreservesThombstoneKey(t *testing.T) {
	unknownObj := 100
	endpoint := cache.DeletedFinalStateUnknown{
		Key: "default/some-service",
		Obj: unknownObj,
	}

	result, err := transformEndpoint(hivetest.Logger(t), endpoint)
	require.NoError(t, err)
	tombstone, ok := result.(cache.DeletedFinalStateUnknown)
	require.True(t, ok)
	require.Equal(t, endpoint.Key, tombstone.Key)
}
