// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFRecorderCmd represents the bpf_recorder command
var BPFRecorderCmd = &cobra.Command{
	Use:   "recorder",
	Short: "PCAP recorder",
}

func init() {
	BPFCmd.AddCommand(BPFRecorderCmd)
}
