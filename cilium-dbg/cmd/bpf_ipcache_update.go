// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/types"
	"github.com/spf13/cobra"
)

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheUpdateCmd)

	bpfIPCacheUpdateCmd.PersistentFlags().String("ip", "", "IP address, e.g. 10.244.1.217/32")
	bpfIPCacheUpdateCmd.PersistentFlags().String("tunnelendpoint", "", "Tunnel endpoint, e.g. 172.21.0.3")
	bpfIPCacheUpdateCmd.PersistentFlags().Uint32("identity", 0, "Identity, e.g. 14170")
	bpfIPCacheUpdateCmd.PersistentFlags().Uint8("encryptkey", 0, "Encrypt key")
	bpfIPCacheUpdateCmd.PersistentFlags().Bool("skiptunnel", false, "Skip tunnel")
}

var bpfIPCacheUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an entry for an ip",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache update")

		ipString, err := cmd.Flags().GetString("ip")
		if err != nil {
			Usagef(cmd, "Invalid IP. "+usage)
		}
		_, ipnet, err := net.ParseCIDR(ipString)
		if ipnet == nil || err != nil {
			Usagef(cmd, "Invalid IP. "+usage)
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

		key := ipcache.NewKey(ipnet.IP, ipnet.Mask, 0)
		value := ipcache.RemoteEndpointInfo{
			SecurityIdentity: identity,
			TunnelEndpoint:   types.IPv4(tunnelEndpoint),
			Key:              encryptKey,
			Flags:            flags,
		}
		if err := ipcache.IPCacheMap().Update(&key, &value); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating entry %s: %v\n", key, err)
			os.Exit(1)
		}

		fmt.Printf("Updated entry %s => %s\n", &key, &value)
	},
}
