// Copyright 2018 Authors of Cilium
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

package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/spf13/cobra"
)

const (
	reasonTitle    = "REASON"
	directionTitle = "DIRECTION"
	packetsTitle   = "PACKETS"
	bytesTitle     = "BYTES"
)

type metricsMapFormat int

const (
	oldMetricsMapFormat metricsMapFormat = iota
	newMetricsMapFormat
)

type metricsRow struct {
	reasonCode int
	reasonDesc string
	direction  string
	packets    int
	bytes      int
}

type metricValues struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type metric struct {
	Reason      uint64                  `json:"reason"`
	Description string                  `json:"description"`
	Values      map[string]metricValues `json:"values"`
}

type metrics []metric

var bpfMetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List BPF datapath traffic metrics",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf metrics list")
		listMetrics(metricsmap.OldMetrics, metricsmap.Metrics)
	},
}

func listMetrics(oldMap, newMap metricsmap.MetricsMap) {
	oldBPFMetricsList := make(map[string]string)
	oldBPFMetricsCallback := func(key bpf.MapKey, value bpf.MapValue) {
		oldBPFMetricsList[key.String()] = value.String()
	}
	if err := oldMap.DumpWithCallback(oldBPFMetricsCallback); err != nil {
		fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
		os.Exit(1)
	}

	bpfMetricsList := make(map[string]string)
	bpfMetricsCallback := func(key bpf.MapKey, value bpf.MapValue) {
		bpfMetricsList[key.String()] = value.String()
	}
	if err := newMap.DumpWithCallback(bpfMetricsCallback); err != nil {
		fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
		os.Exit(1)
	}

	if command.OutputJSON() {
		listJSONMetrics(oldBPFMetricsList, bpfMetricsList)
		return
	}

	listHumanReadableMetrics(oldBPFMetricsList, bpfMetricsList)
}

type metricsWithFormat struct {
	metrics map[string]string
	format  metricsMapFormat
}

func mergeOldAndNewMaps(oldBPFMetricsList, bpfMetricsList map[string]string) []metric {
	metricsByReason := map[int]metric{}

	metricsWithFormat := []metricsWithFormat{
		{oldBPFMetricsList, oldMetricsMapFormat},
		{bpfMetricsList, newMetricsMapFormat},
	}

	for _, m := range metricsWithFormat {
		for key, value := range m.metrics {
			row, err := extractRow(key, value, m.format)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot extract metric row: %s\n", err)
				continue
			}

			if _, ok := metricsByReason[row.reasonCode]; !ok {
				metricsByReason[row.reasonCode] = metric{
					Reason:      uint64(row.reasonCode),
					Description: monitorAPI.DropReason(uint8(row.reasonCode)),
					Values:      map[string]metricValues{},
				}
			}

			direction := strings.ToLower(row.direction)

			metrics, _ := metricsByReason[row.reasonCode].Values[direction]
			metricsByReason[row.reasonCode].Values[direction] = metricValues{
				Packets: metrics.Packets + uint64(row.packets),
				Bytes:   metrics.Bytes + uint64(row.bytes),
			}
		}
	}

	metrics := []metric{}
	for _, v := range metricsByReason {
		metrics = append(metrics, v)
	}

	return metrics
}

func listJSONMetrics(oldBPFMetricsList, bpfMetricsList map[string]string) {
	metrics := mergeOldAndNewMaps(oldBPFMetricsList, bpfMetricsList)
	if err := command.PrintOutput(metrics); err != nil {
		fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
		os.Exit(1)
	}
}

func listHumanReadableMetrics(oldBPFMetricsList, bpfMetricsList map[string]string) {
	if len(oldBPFMetricsList) == 0 && len(bpfMetricsList) == 0 {
		fmt.Fprintf(os.Stderr, "No entries found.\n")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", reasonTitle, directionTitle, packetsTitle, bytesTitle)

	const numColumns = 4
	rows := [][numColumns]string{}

	for _, metrics := range mergeOldAndNewMaps(oldBPFMetricsList, bpfMetricsList) {
		for direction, metric := range metrics.Values {
			rows = append(rows, [numColumns]string{metrics.Description, strings.ToUpper(direction),
				fmt.Sprintf("%d", metric.Packets), fmt.Sprintf("%d", metric.Bytes)})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		for k := 0; k < numColumns; k++ {
			c := strings.Compare(rows[i][k], rows[j][k])

			if c != 0 {
				return c < 0
			}
		}

		return false
	})

	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r[0], r[1], r[2], r[3])
	}

	w.Flush()
}

func oldToNewDirection(direction int) (int, bool) {
	switch direction {
	case 1: // old INGRESS
		return 1, true
	case 2: // old EGRESS
		return 0, true
	default:
		return 0, false
	}
}

func extractRow(key, value string, format metricsMapFormat) (*metricsRow, error) {
	reasonCodeStr, directionCodeStr, ok := extractTwoValues(key)
	if !ok {
		return nil, fmt.Errorf("cannot extract reason and traffic direction from map's key \"%s\"", key)
	}

	reasonCode, err := strconv.Atoi(reasonCodeStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse reason: %s", err)
	}

	directionCode, err := strconv.Atoi(directionCodeStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse direction: %s", err)
	}

	packetsStr, bytesStr, ok := extractTwoValues(value)
	if !ok {
		return nil, fmt.Errorf("cannot extract packets and bytes counters from map's value \"%s\"", value)
	}

	packets, err := strconv.Atoi(packetsStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse packets counter: %s", err)
	}

	bytes, err := strconv.Atoi(bytesStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse bytes counter: %s", err)
	}

	reasonDesc := monitorAPI.DropReason(uint8(reasonCode))
	if format == oldMetricsMapFormat {
		var ok bool
		if directionCode, ok = oldToNewDirection(directionCode); !ok {
			return nil, fmt.Errorf("invalid direction code")
		}
	}
	direction := metricsmap.MetricDirection(uint8(directionCode))

	return &metricsRow{reasonCode, reasonDesc, direction, packets, bytes}, nil
}

func extractTwoValues(str string) (string, string, bool) {
	tmp := strings.Split(str, " ")
	if len(tmp) != 2 {
		return "", "", false
	}

	a := strings.Split(tmp[0], ":")
	if len(a) != 2 {
		return "", "", false
	}

	b := strings.Split(tmp[1], ":")
	if len(b) != 2 {
		return "", "", false
	}

	return a[1], b[1], true
}

func init() {
	bpfMetricsCmd.AddCommand(bpfMetricsListCmd)
	command.AddJSONOutput(bpfMetricsListCmd)
}
