// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfRecorderCmd represents the bpf_recorder command
var bpfRecorderCmd = &cobra.Command{
	Use:   "recorder",
	Short: "PCAP recorder",
}

func init() {
	bpfCmd.AddCommand(bpfRecorderCmd)
}
