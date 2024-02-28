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
	reasonCode uint8
	reasonDesc string
	direction  string
	packets    uint64
	bytes      uint64
}

type jsonMetric struct {
	Reason    string `json:"reason"`
	Direction string `json:"direction"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
}

type jsonMetrics []*jsonMetric

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

	// All keys in the metrics map that have these fields in common will have
	// their byte and packet counters summed and presented as a single metric.
	// This is to allow newer Cilium versions to make use of the reserved bits
	// in the metricsmap key without breaking older versions of the agent. From
	// the old agent's perspective, this would cause duplicate metrics to appear.
	type key struct {
		reason    string
		direction string
	}

	metrics := make(map[key]*jsonMetric)

	for _, row := range bpfMetricsList {
		k := key{
			reason:    monitorAPI.DropReason(row.reasonCode),
			direction: strings.ToLower(row.direction),
		}

		if _, ok := metrics[k]; !ok {
			metrics[k] = &jsonMetric{
				Reason:    monitorAPI.DropReason(row.reasonCode),
				Direction: strings.ToLower(row.direction),
			}
		}

		metrics[k].Packets += row.packets
		metrics[k].Bytes += row.bytes
	}

	var out jsonMetrics
	for _, v := range metrics {
		out = append(out, v)
	}

	if err := command.PrintOutput(out); err != nil {
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
	return &metricsRow{
		key.Reason,
		key.DropForwardReason(),
		key.Direction(),
		values.Count(),
		values.Bytes(),
	}
}

func init() {
	BPFMetricsCmd.AddCommand(bpfMetricsListCmd)
	command.AddOutputOption(bpfMetricsListCmd)
}
