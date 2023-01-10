// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

const (
	reasonTitle    = "REASON"
	directionTitle = "DIRECTION"
	packetsTitle   = "PACKETS"
	bytesTitle     = "BYTES"
)

type metricsRow struct {
	reasonCode int
	reasonDesc string
	direction  string
	packets    int
	bytes      int
}

type jsonMetricValues struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type jsonMetric struct {
	Reason      uint64                      `json:"reason"`
	Description string                      `json:"description"`
	Values      map[string]jsonMetricValues `json:"values"`
}

type jsonMetrics []jsonMetric

var bpfMetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List BPF datapath traffic metrics",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf metrics list")
		listMetrics(&metricsmap.Metrics)
	},
}

func listMetrics(m metricsmap.MetricsMap) {
	bpfMetricsList := []*metricsRow{}

	cb := func(key *metricsmap.Key, values *metricsmap.Values) {
		bpfMetricsList = append(bpfMetricsList, extractRow(key, values))
	}

	if err := m.IterateWithCallback(cb); err != nil {
		fmt.Fprintf(os.Stderr, "error iterating BPF metrics map: %v\n", err)
		os.Exit(1)
	}

	if command.OutputOption() {
		listJSONMetrics(bpfMetricsList)
		return
	}

	listHumanReadableMetrics(bpfMetricsList)
}

func listJSONMetrics(bpfMetricsList []*metricsRow) {
	if len(bpfMetricsList) == 0 {
		fmt.Fprintf(os.Stderr, "No entries found.\n")
		return
	}

	metricsByReason := map[int]jsonMetric{}

	for _, row := range bpfMetricsList {
		if _, ok := metricsByReason[row.reasonCode]; !ok {
			metricsByReason[row.reasonCode] = jsonMetric{
				Reason:      uint64(row.reasonCode),
				Description: monitorAPI.DropReason(uint8(row.reasonCode)),
				Values:      map[string]jsonMetricValues{},
			}
		}

		direction := strings.ToLower(row.direction)

		metricsByReason[row.reasonCode].Values[direction] = jsonMetricValues{
			Packets: uint64(row.packets),
			Bytes:   uint64(row.bytes),
		}
	}

	metrics := jsonMetrics{}
	for _, v := range metricsByReason {
		metrics = append(metrics, v)
	}

	if err := command.PrintOutput(metrics); err != nil {
		fmt.Fprintf(os.Stderr, "error getting output of map in %s: %s\n", command.OutputOptionString(), err)
		os.Exit(1)
	}
}

func listHumanReadableMetrics(bpfMetricsList []*metricsRow) {
	if len(bpfMetricsList) == 0 {
		fmt.Fprintf(os.Stderr, "No entries found.\n")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", reasonTitle, directionTitle, packetsTitle, bytesTitle)

	const numColumns = 4
	rows := [][numColumns]string{}

	for _, row := range bpfMetricsList {
		rows = append(rows, [numColumns]string{row.reasonDesc, row.direction, fmt.Sprintf("%d", row.packets), fmt.Sprintf("%d", row.bytes)})
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

func extractRow(key *metricsmap.Key, values *metricsmap.Values) *metricsRow {
	return &metricsRow{int(key.Reason), key.DropForwardReason(), key.Direction(), int(values.Count()), int(values.Bytes())}
}

func init() {
	bpfMetricsCmd.AddCommand(bpfMetricsListCmd)
	command.AddOutputOption(bpfMetricsListCmd)
}
