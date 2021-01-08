// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package cmd

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"

	. "gopkg.in/check.v1"
)

type BPFMetricsMapSuite struct{}

var _ = Suite(&BPFMetricsMapSuite{})

func (s *BPFMetricsMapSuite) TestDumpMetrics(c *C) {
	metricsMap := []interface{}{
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
			},
		),
	}

	desc := func(x int) string {
		return monitorAPI.DropReason(uint8(x))
	}

	dir := func(d int) string {
		return strings.ToLower(metricsmap.MetricDirection(uint8(d)))
	}

	jsonEncodedMetricsMap := jsonMetrics{
		jsonMetric{
			Reason:      0,
			Description: desc(0),
			Values: map[string]jsonMetricValues{
				dir(1): {
					Packets: 100,
					Bytes:   1000,
				},
				dir(2): {
					Packets: 200,
					Bytes:   2000,
				},
			},
		},
		jsonMetric{
			Reason:      132,
			Description: desc(132),
			Values: map[string]jsonMetricValues{
				dir(2): {
					Packets: 300,
					Bytes:   3000,
				},
			},
		},
	}

	rawDump := dumpAndRead(metricsMap, func(maps []interface{}, args ...interface{}) {
		for _, m := range maps {
			listMetrics(m.(*mockmaps.MetricsMockMap))
		}
	}, c)

	var jsonEncodedMetricsMapDump jsonMetrics
	err := json.Unmarshal([]byte(rawDump), &jsonEncodedMetricsMapDump)
	c.Assert(err, IsNil, Commentf("invalid JSON output: '%s', '%s'", err, rawDump))

	sort.Slice(jsonEncodedMetricsMap, func(i, j int) bool {
		return jsonEncodedMetricsMap[i].Reason <= jsonEncodedMetricsMap[j].Reason
	})

	sort.Slice(jsonEncodedMetricsMapDump, func(i, j int) bool {
		return jsonEncodedMetricsMapDump[i].Reason <= jsonEncodedMetricsMapDump[j].Reason
	})

	c.Assert(jsonEncodedMetricsMap, checker.DeepEquals, jsonEncodedMetricsMapDump)
}
