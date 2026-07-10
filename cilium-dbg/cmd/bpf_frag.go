// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFFragCmd represents the bpf command
var BPFFragCmd = &cobra.Command{
	Use:     "frag",
	Aliases: []string{"fragments"},
	Short:   "Manage the IPv4 datagram fragments",
}

func init() {
	BPFCmd.AddCommand(BPFFragCmd)
}
