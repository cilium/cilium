// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheDeleteCmd)

	bpfIPCacheDeleteCmd.PersistentFlags().Uint16("clusterid", 0, "Cluster ID")
}

var bpfIPCacheDeleteCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete an entry for a prefix",
	Example: "cilium bpf ipcache delete 10.244.3.110/32 --clusterid 1",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache delete")

		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "No prefix provided. "+usage)
		}

		arg := args[0]

		clusterID, err := cmd.Flags().GetUint16("clusterid")
		if err != nil {
			Usagef(cmd, "Invalid cluster ID. "+usage)
		}

		prefix, err := netip.ParsePrefix(arg)
		if err != nil {
			Usagef(cmd, "Invalid prefix address. "+usage)
		}

		key := ipcache.NewKey(prefix, clusterID)
		if err := ipcache.IPCacheMap(nil).Delete(&key); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting entry %s: %v\n", key, err)
			os.Exit(1)
		}

		fmt.Printf("Deleted entry %s\n", key)
	},
}
