// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMock(t *testing.T) {
	api := NewMockMetrics()
	api.ObserveAPICall("DescribeNetworkInterfaces", "success", 2.0)
	require.Equal(t, 2.0, api.APICall("DescribeNetworkInterfaces", "success"))
	api.ObserveRateLimit("DescribeNetworkInterfaces", time.Second)
	api.ObserveRateLimit("DescribeNetworkInterfaces", time.Second)
	require.Equal(t, 2*time.Second, api.RateLimit("DescribeNetworkInterfaces"))
}
