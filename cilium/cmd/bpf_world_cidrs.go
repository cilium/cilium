// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFWorldCIDRCmd represents the bpf command
var BPFWorldCIDRCmd = &cobra.Command{
	Use:   "world",
	Short: "List the world CIDRs",
}

func init() {
	BPFCmd.AddCommand(BPFWorldCIDRCmd)
}
