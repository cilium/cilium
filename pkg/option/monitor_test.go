// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyMonitorAggregationLevel(t *testing.T) {
	require.NoError(t, VerifyMonitorAggregationLevel("", ""))
	require.NoError(t, VerifyMonitorAggregationLevel("", "none"))
	require.NoError(t, VerifyMonitorAggregationLevel("", "disabled"))
	require.NoError(t, VerifyMonitorAggregationLevel("", "lowest"))
	require.NoError(t, VerifyMonitorAggregationLevel("", "low"))
	require.NoError(t, VerifyMonitorAggregationLevel("", "medium"))
	require.NoError(t, VerifyMonitorAggregationLevel("", "max"))
	require.NoError(t, VerifyMonitorAggregationLevel("", "maximum"))
	require.NoError(t, VerifyMonitorAggregationLevel("", "LoW"))
	require.Error(t, VerifyMonitorAggregationLevel("", "disable"))
}

func TestParseMonitorAggregationLevel(t *testing.T) {
	level, err := ParseMonitorAggregationLevel("2")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelLow, level)

	_, err = ParseMonitorAggregationLevel(strconv.Itoa(int(MonitorAggregationLevelMax) + 1))
	require.Error(t, err)

	_, err = ParseMonitorAggregationLevel("-1")
	require.Error(t, err)

	_, err = ParseMonitorAggregationLevel("foo")
	require.Error(t, err)

	level, err = ParseMonitorAggregationLevel("")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelNone, level)

	level, err = ParseMonitorAggregationLevel("none")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelNone, level)

	level, err = ParseMonitorAggregationLevel("disabled")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelNone, level)

	level, err = ParseMonitorAggregationLevel("lowest")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelLowest, level)

	level, err = ParseMonitorAggregationLevel("low")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelLow, level)

	level, err = ParseMonitorAggregationLevel("medium")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelMedium, level)

	level, err = ParseMonitorAggregationLevel("max")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelMax, level)

	level, err = ParseMonitorAggregationLevel("maximum")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelMax, level)

	level, err = ParseMonitorAggregationLevel("LOW")
	require.NoError(t, err)
	require.Equal(t, MonitorAggregationLevelLow, level)
}
