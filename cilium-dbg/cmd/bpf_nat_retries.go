// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFNatRetriesCmd represents the bpf_nat_retries command
var BPFNatRetriesCmd = &cobra.Command{
	Use:   "retries",
	Short: "Histogram of retries",
}

func init() {
	BPFNatCmd.AddCommand(BPFNatRetriesCmd)
}
