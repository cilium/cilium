// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheUpdateCmd)

	bpfIPCacheUpdateCmd.PersistentFlags().String("tunnelendpoint", "", "Tunnel endpoint")
	bpfIPCacheUpdateCmd.PersistentFlags().Uint32("identity", 0, "Identity")
	bpfIPCacheUpdateCmd.PersistentFlags().Uint8("encryptkey", 0, "Encrypt key")
	bpfIPCacheUpdateCmd.PersistentFlags().Bool("skiptunnel", false, "Skip tunnel")
	bpfIPCacheUpdateCmd.PersistentFlags().Uint16("clusterid", 0, "Cluster ID")
}

var bpfIPCacheUpdateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Update an entry for a prefix",
	Example: "cilium bpf ipcache update 10.244.3.110/32 --tunnelendpoint 172.21.0.2 --identity 6 --encryptkey 255 --clusterid 0",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache update")

		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "No prefix provided. "+usage)
		}

		prefix, err := netip.ParsePrefix(args[0])
		if err != nil {
			Usagef(cmd, "Invalid prefix address. "+usage)
		}

		tunnelEndpointString, err := cmd.Flags().GetString("tunnelendpoint")
		if err != nil {
			Usagef(cmd, "Invalid tunnel endpoint. "+usage)
		}
		tunnelEndpoint := net.ParseIP(tunnelEndpointString)
		if tunnelEndpoint == nil {
			Usagef(cmd, "Invalid tunnel endpoint. "+usage)
		}

		identity, err := cmd.Flags().GetUint32("identity")
		if err != nil {
			Usagef(cmd, "Invalid identity. "+usage)
		}

		encryptKey, err := cmd.Flags().GetUint8("encryptkey")
		if err != nil {
			Usagef(cmd, "Invalid encrypt key. "+usage)
		}

		skipTunnel, err := cmd.Flags().GetBool("skiptunnel")
		if err != nil {
			Usagef(cmd, "Invalid skip tunnel. "+usage)
		}
		var flags ipcache.RemoteEndpointInfoFlags
		if skipTunnel {
			flags |= ipcache.FlagSkipTunnel
		}
		clusterID, err := cmd.Flags().GetUint16("clusterid")
		if err != nil {
			Usagef(cmd, "Invalid cluster ID. "+usage)
		}

		ip := net.IP(prefix.Addr().AsSlice())
		mask := net.CIDRMask(prefix.Bits(), 32)
		key := ipcache.NewKey(ip, mask, clusterID)
		value := ipcache.NewValue(identity, tunnelEndpoint, encryptKey, flags)
		if err := ipcache.IPCacheMap().Update(&key, &value); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating entry %s: %v\n", key, err)
			os.Exit(1)
		}

		fmt.Printf("Updated entry %s => %s\n", &key, &value)
	},
}
