// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFBandwidthCmd represents the bpf_bandwidth command
var BPFBandwidthCmd = &cobra.Command{
	Use:   "bandwidth",
	Short: "BPF datapath bandwidth settings",
}

func init() {
	BPFCmd.AddCommand(BPFBandwidthCmd)
}
