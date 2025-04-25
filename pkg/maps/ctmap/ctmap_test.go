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
	cachedGCInterval = time.Duration(0)

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
	cachedGCInterval = time.Minute
	logger := hivetest.Logger(t)
	require.Equal(t, time.Minute, GetInterval(logger, cachedGCInterval, 0.1))

	// Setting ConntrackGCInterval overrides the calculation
	oldInterval := option.Config.ConntrackGCInterval
	option.Config.ConntrackGCInterval = 10 * time.Second
	require.Equal(t, 10*time.Second, GetInterval(logger, cachedGCInterval, 0.1))
	option.Config.ConntrackGCInterval = oldInterval
	require.Equal(t, time.Minute, GetInterval(logger, cachedGCInterval, 0.1))

	// Setting ConntrackGCMaxInterval limits the maximum interval
	oldMaxInterval := option.Config.ConntrackGCMaxInterval
	option.Config.ConntrackGCMaxInterval = 20 * time.Second
	require.Equal(t, 20*time.Second, GetInterval(logger, cachedGCInterval, 0.1))
	option.Config.ConntrackGCMaxInterval = oldMaxInterval
	require.Equal(t, time.Minute, GetInterval(logger, cachedGCInterval, 0.1))

	cachedGCInterval = time.Duration(0)
}

func TestFilterMapsByProto(t *testing.T) {
	maps := []*Map{
		newMap("tcp4", mapTypeIPv4TCPGlobal),
		newMap("any4", mapTypeIPv4AnyGlobal),
		newMap("tcp6", mapTypeIPv6TCPGlobal),
		newMap("any6", mapTypeIPv6AnyGlobal),
	}

	ctMapTCP, ctMapAny := FilterMapsByProto(maps, CTMapIPv4)
	require.Equal(t, mapTypeIPv4TCPGlobal, ctMapTCP.mapType)
	require.Equal(t, mapTypeIPv4AnyGlobal, ctMapAny.mapType)

	ctMapTCP, ctMapAny = FilterMapsByProto(maps, CTMapIPv6)
	require.Equal(t, mapTypeIPv6TCPGlobal, ctMapTCP.mapType)
	require.Equal(t, mapTypeIPv6AnyGlobal, ctMapAny.mapType)

	maps = maps[0:2] // remove ipv6 maps
	ctMapTCP, ctMapAny = FilterMapsByProto(maps, CTMapIPv6)
	require.Nil(t, ctMapTCP)
	require.Nil(t, ctMapAny)
}
