// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFIPCacheCmd represents the bpf command
var BPFIPCacheCmd = &cobra.Command{
	Use:   "ipcache",
	Short: "Manage the IPCache mappings for IP/CIDR <-> Identity",
}

func init() {
	BPFCmd.AddCommand(BPFIPCacheCmd)
}
