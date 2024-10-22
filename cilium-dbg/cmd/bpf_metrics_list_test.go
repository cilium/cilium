// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/maps/metricsmap"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
)

func TestDumpMetrics(t *testing.T) {
	metricsMap := []*mockmaps.MetricsMockMap{
		mockmaps.NewMetricsMockMap(
			[]mockmaps.MetricsRecord{
				{
					Key:    metricsmap.Key{Reason: 0, Dir: 1},
					Values: metricsmap.Values{{Count: 100, Bytes: 1000}},
				},
				{
					Key:    metricsmap.Key{Reason: 0, Dir: 2},
					Values: metricsmap.Values{{Count: 200, Bytes: 2000}},
				},
				{
					Key:    metricsmap.Key{Reason: 132, Dir: 2},
					Values: metricsmap.Values{{Count: 300, Bytes: 3000}},
				},
				// 'Duplicate' metric that had reserved bits of its key utilized in a
				// newer version of Cilium. This should result in counters being summed
				// with other keys with matching known fields. For example, Cilium 1.16
				// adds line and file info to each metric, which older versions will
				// ignore. In this case, all keys with the same reason and direction
				// should be summed and presented as a single metric.
				{
					Key:    metricsmap.Key{Reason: 132, Dir: 2},
					Values: metricsmap.Values{{Count: 1, Bytes: 1}},
				},
				{
					Key:    metricsmap.Key{Reason: 140, Dir: 2, Line: 1337, File: 1},
					Values: metricsmap.Values{{Count: 400, Bytes: 4000}},
				},
			},
		),
	}

	reason := func(x int) string {
		return monitorAPI.DropReason(uint8(x))
	}

	dir := func(d int) string {
		return strings.ToLower(metricsmap.MetricDirection(uint8(d)))
	}

	file := func(f uint8) string {
		return monitorAPI.BPFFileName(f)
	}

	want := jsonMetrics{
		{
			Reason:    reason(0),
			Direction: dir(1),
			Packets:   100,
			Bytes:     1000,
			File:      file(0),
		},
		{
			Reason:    reason(0),
			Direction: dir(2),
			Packets:   200,
			Bytes:     2000,
			File:      file(0),
		},
		{
			Reason:    reason(132),
			Direction: dir(2),
			Packets:   301,
			Bytes:     3001,
			File:      file(0),
		},
		{
			Reason:    reason(140),
			Direction: dir(2),
			Line:      1337,
			File:      file(1),
			Packets:   400,
			Bytes:     4000,
		},
	}

	rawDump := dumpAndRead(t, metricsMap, func(maps []*mockmaps.MetricsMockMap, args ...interface{}) {
		for _, m := range maps {
			listMetrics(m)
		}
	})

	var got jsonMetrics
	err := json.Unmarshal([]byte(rawDump), &got)
	require.NoError(t, err, "invalid JSON output: '%s', '%s'", err, rawDump)

	sort.Slice(got, func(i, j int) bool {
		return got[i].Packets <= got[j].Packets
	})
	require.EqualValues(t, want, got)
}
