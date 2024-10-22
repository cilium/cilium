// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFVtepCmd represents the bpf command
var BPFVtepCmd = &cobra.Command{
	Use:   "vtep",
	Short: "Manage the VTEP mappings for IP/CIDR <-> VTEP MAC/IP",
}

func init() {
	BPFCmd.AddCommand(BPFVtepCmd)
}
