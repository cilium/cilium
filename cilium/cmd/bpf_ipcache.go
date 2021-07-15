// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfIPCacheCmd represents the bpf command
var bpfIPCacheCmd = &cobra.Command{
	Use:   "ipcache",
	Short: "Manage the IPCache mappings for IP/CIDR <-> Identity",
}

func init() {
	bpfCmd.AddCommand(bpfIPCacheCmd)
}
