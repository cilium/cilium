// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFNatCmd represents the bpf_nat command
var BPFNatCmd = &cobra.Command{
	Use:   "nat",
	Short: "NAT mapping tables",
}

func init() {
	BPFCmd.AddCommand(BPFNatCmd)
}
