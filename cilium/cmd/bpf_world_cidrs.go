// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfWorldCIDRCmd represents the bpf command
var bpfWorldCIDRCmd = &cobra.Command{
	Use:   "world",
	Short: "List the world CIDRs",
}

func init() {
	bpfCmd.AddCommand(bpfWorldCIDRCmd)
}
