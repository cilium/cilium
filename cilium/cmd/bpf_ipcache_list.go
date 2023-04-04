// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

const (
	ipAddrTitle   = "IP PREFIX/ADDRESS"
	identityTitle = "IDENTITY"
)

var (
	ipCacheListUsage = "List endpoint IPs (local and remote) and their corresponding security identities."
)

var bpfIPCacheListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List endpoint IPs (local and remote) and their corresponding security identities",
	Long:    ipCacheListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache list")

		bpfIPCacheList := make(map[string][]string)
		if err := ipcache.IPCacheMap().Dump(bpfIPCacheList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfIPCacheList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in %s: %s\n", command.OutputOptionString(), err)
				os.Exit(1)
			}
			return
		}

		if len(bpfIPCacheList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter(ipAddrTitle, identityTitle, bpfIPCacheList)
		}
	},
}

func init() {
	bpfIPCacheCmd.AddCommand(bpfIPCacheListCmd)
	command.AddOutputOption(bpfIPCacheListCmd)
}
