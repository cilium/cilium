// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/spf13/cobra"
)

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheDeleteCmd)
}

var bpfIPCacheDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete an entry for an ip",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache delete")

		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "No ip provided. "+usage)
		}

		arg := args[0]

		ip := net.ParseIP(arg)
		if ip == nil {
			Usagef(cmd, "Invalid ip address. "+usage)
		}

		key := ipcache.NewKey(ip, nil, 0)
		if err := ipcache.IPCacheMap().Delete(&key); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting entry %s: %v\n", key, err)
			os.Exit(1)
		}

		fmt.Printf("Deleted entry %s\n", key)
	},
}
