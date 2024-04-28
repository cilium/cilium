// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyMonitorAggregationLevel(t *testing.T) {
	require.Nil(t, VerifyMonitorAggregationLevel("", ""))
	require.Nil(t, VerifyMonitorAggregationLevel("", "none"))
	require.Nil(t, VerifyMonitorAggregationLevel("", "disabled"))
	require.Nil(t, VerifyMonitorAggregationLevel("", "lowest"))
	require.Nil(t, VerifyMonitorAggregationLevel("", "low"))
	require.Nil(t, VerifyMonitorAggregationLevel("", "medium"))
	require.Nil(t, VerifyMonitorAggregationLevel("", "max"))
	require.Nil(t, VerifyMonitorAggregationLevel("", "maximum"))
	require.Nil(t, VerifyMonitorAggregationLevel("", "LoW"))
	require.NotNil(t, VerifyMonitorAggregationLevel("", "disable"))
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
