// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFSubnetCmd represents the bpf subnet command
var BPFSubnetCmd = &cobra.Command{
	Use:   "subnet",
	Short: "Manage the subnet identity mappings for hybrid routing",
}

func init() {
	BPFCmd.AddCommand(BPFSubnetCmd)
}
