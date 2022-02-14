// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfVtepCmd represents the bpf command
var bpfVtepCmd = &cobra.Command{
	Use:   "vtep",
	Short: "Manage the VTEP mappings for IP/CIDR <-> VTEP MAC/IP",
}

func init() {
	bpfCmd.AddCommand(bpfVtepCmd)
}
