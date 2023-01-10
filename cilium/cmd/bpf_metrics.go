// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfMetricsCmd represents the bpf_metrics command
var bpfMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "BPF datapath traffic metrics",
}

func init() {
	bpfCmd.AddCommand(bpfMetricsCmd)
}
