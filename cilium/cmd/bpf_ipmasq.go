// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfIPMasqCmd represents the bpf command
var bpfIPMasqCmd = &cobra.Command{
	Use:   "ipmasq",
	Short: "ip-masq-agent CIDRs",
}

func init() {
	bpfCmd.AddCommand(bpfIPMasqCmd)
}
