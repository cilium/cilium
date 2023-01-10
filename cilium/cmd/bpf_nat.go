// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfNatCmd represents the bpf_nat command
var bpfNatCmd = &cobra.Command{
	Use:   "nat",
	Short: "NAT mapping tables",
}

func init() {
	bpfCmd.AddCommand(bpfNatCmd)
}
