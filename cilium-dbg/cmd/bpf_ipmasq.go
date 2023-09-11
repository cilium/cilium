// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFIPMasqCmd represents the bpf command
var BPFIPMasqCmd = &cobra.Command{
	Use:   "ipmasq",
	Short: "ip-masq-agent CIDRs",
}

func init() {
	BPFCmd.AddCommand(BPFIPMasqCmd)
}
