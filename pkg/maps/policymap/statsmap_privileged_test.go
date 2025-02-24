// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatMap(t *testing.T) {
	policyMap := setupPolicyMapPrivilegedTestSuite(t)
	require.NotNil(t, policyMap)

	testMap := policyMap.stats
	require.NotNil(t, testMap)

	fooKey := NewKey(1, 1, 1, 1, SinglePortPrefixLen)

	err := testMap.ClearStat(0, fooKey)
	require.NoError(t, err)

	packets, bytes := testMap.GetStat(0, fooKey)
	require.Equal(t, StatNotAvailable, packets)
	require.Equal(t, StatNotAvailable, bytes)

	err = testMap.ZeroStat(0, fooKey)
	require.NoError(t, err)

	packets, bytes = testMap.GetStat(0, fooKey)
	require.Equal(t, uint64(0), packets)
	require.Equal(t, uint64(0), bytes)

	err = testMap.ClearStat(0, fooKey)
	require.NoError(t, err)
}
