// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
)

var bpfMetricsFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Clear BPF datapath traffic metrics (test purpose only)",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf metrics flush")

		mm, err := metricsmap.LoadMetricsMap(log)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading BPF metrics map: %v\n", err)
			os.Exit(1)
		}

		flushMetrics(mm)
	},
}

func flushMetrics(m metricsmap.MetricsMap) {
	cb := func(key *metricsmap.Key, values *metricsmap.Values) {
		if err := m.Delete(key); err != nil {
			fmt.Fprintf(os.Stderr, "error removing key from BPF metrics map: %v\n", err)
			os.Exit(1)
		}
	}

	if err := m.IterateWithCallback(cb); err != nil {
		fmt.Fprintf(os.Stderr, "error iterating BPF metrics map: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	BPFMetricsCmd.AddCommand(bpfMetricsFlushCmd)
	command.AddOutputOption(bpfMetricsFlushCmd)
}
