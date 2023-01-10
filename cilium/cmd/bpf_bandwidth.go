// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfBandwidthCmd represents the bpf_bandwidth command
var bpfBandwidthCmd = &cobra.Command{
	Use:   "bandwidth",
	Short: "BPF datapath bandwidth settings",
}

func init() {
	bpfCmd.AddCommand(bpfBandwidthCmd)
}
