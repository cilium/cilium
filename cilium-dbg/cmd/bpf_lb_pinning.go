// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/types"
)

var LbPinCmd = &cobra.Command{
	Use:   "pinning",
	Short: "Load-balancing pinning configuration",
}

var LbPinUpdateCmd = &cobra.Command{
	Args:  cobra.ExactArgs(2),
	Use:   "update",
	Short: "Update LB pinning map entry",
	Long:  "Update LB pinning map entry",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb pinning update <svc_ip> <node_ip>")

		var key lbmaps.LbPinning4Key
		var val lbmaps.LbPinning4Value

		svc_ip := net.ParseIP(args[0]).To4()
		if svc_ip == nil {
			Fatalf("Unable to parse IP '%s'", args[1])
		}

		node_ip := net.ParseIP(args[1]).To4()
		if node_ip == nil {
			Fatalf("Unable to parse IP '%s'", args[1])
		}

		key.ServiceIP = types.IPv4(svc_ip)
		val.NodeIP = types.IPv4(node_ip)

		if err := lbmaps.NewPinningMap(0).Update(&key, &val); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

var LbPinDelCmd = &cobra.Command{
	Args:  cobra.ExactArgs(1),
	Use:   "delete",
	Short: "Delete LB pinning map entry",
	Long:  "Delete LB pinning map entry",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb pinning update <svc_ip> <node_ip>")

		var key lbmaps.LbPinning4Key

		svc_ip := net.ParseIP(args[0]).To4()
		if svc_ip == nil {
			Fatalf("error parsing cidr %s: %s", args[0])
		}

		key.ServiceIP = types.IPv4(svc_ip)

		if _, err := lbmaps.NewPinningMap(0).SilentDelete(&key); err != nil {
			fmt.Fprintf(os.Stderr, "error deleting contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

const (
	serviceTitle     = "SERVICE ADDRESS"
	nodeAddressTitle = "NODE ADDRESS"
)

var LbPinListCmd = &cobra.Command{
	Args:  cobra.ExactArgs(0),
	Use:   "list",
	Short: "List LB pinning map",
	Long:  "List LB pinning map",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb pinninng list")

		entries := make(map[string][]string)
		if err := lbmaps.NewPinningMap(0).DumpIfExists(entries); err != nil {
			Fatalf("Unable to dump lb4 pinning table: %s", err)
		}

		TablePrinter(serviceTitle, nodeAddressTitle, entries)
	},
}

func init() {
	BPFLBCmd.AddCommand(LbPinCmd)
	LbPinCmd.AddCommand(LbPinListCmd)
	LbPinCmd.AddCommand(LbPinUpdateCmd)
	LbPinCmd.AddCommand(LbPinDelCmd)
}
