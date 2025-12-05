// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	InitMapInfo(nil, true, true, true)
}

func TestCalculateInterval(t *testing.T) {
	require.Equal(t, time.Minute, calculateInterval(time.Minute, 0.1))  // no change
	require.Equal(t, time.Minute, calculateInterval(time.Minute, 0.2))  // no change
	require.Equal(t, time.Minute, calculateInterval(time.Minute, 0.25)) // no change

	require.Equal(t, 36*time.Second, calculateInterval(time.Minute, 0.40))
	require.Equal(t, 24*time.Second, calculateInterval(time.Minute, 0.60))

	require.Equal(t, 15*time.Second, calculateInterval(10*time.Second, 0.01))
	require.Equal(t, 15*time.Second, calculateInterval(10*time.Second, 0.04))

	require.Equal(t, defaults.ConntrackGCMinInterval, calculateInterval(1*time.Second, 0.9))

	require.Equal(t, defaults.ConntrackGCMaxLRUInterval, calculateInterval(24*time.Hour, 0.01))
}

func TestGetInterval(t *testing.T) {
	actualLast := time.Minute
	expectedLast := time.Minute
	logger := hivetest.Logger(t)
	interval := GetInterval(logger, actualLast, expectedLast, 0.1)
	require.Equal(t, time.Minute, interval)
	expectedLast = interval

	option.Config.ConntrackGCInterval = 10 * time.Second
	interval = GetInterval(logger, actualLast, expectedLast, 0.1)
	require.Equal(t, 10*time.Second, interval)

	option.Config.ConntrackGCInterval = 0 // back to default
	interval = GetInterval(logger, actualLast, expectedLast, 0.1)
	require.Equal(t, time.Minute, interval)

	// Setting ConntrackGCMaxInterval limits the maximum interval
	oldMaxInterval := option.Config.ConntrackGCMaxInterval
	option.Config.ConntrackGCMaxInterval = 20 * time.Second
	require.Equal(t, 20*time.Second, GetInterval(logger, actualLast, expectedLast, 0.1))
	option.Config.ConntrackGCMaxInterval = oldMaxInterval
	require.Equal(t, time.Minute, GetInterval(logger, actualLast, expectedLast, 0.1))
}
