// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipcache"

	"github.com/spf13/cobra"
)

const (
	ipAddrTitle   = "IP PREFIX/ADDRESS"
	identityTitle = "IDENTITY"
)

var (
	ipCacheListUsage = "List endpoint IPs (local and remote) and their corresponding security identities.\n" + lpmKernelVersionWarning("cilium_ipcache")
)

var bpfIPCacheListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List endpoint IPs (local and remote) and their corresponding security identities",
	Long:    ipCacheListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache list")

		bpfIPCacheList := make(map[string][]string)
		if err := ipcache.IPCache.Dump(bpfIPCacheList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfIPCacheList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
				os.Exit(1)
			}
			return
		}

		if len(bpfIPCacheList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n%v\n", lpmKernelVersionWarning("cilium_ipcache"))
		} else {
			TablePrinter(ipAddrTitle, identityTitle, bpfIPCacheList)
		}
	},
}

func init() {
	bpfIPCacheCmd.AddCommand(bpfIPCacheListCmd)
	command.AddJSONOutput(bpfIPCacheListCmd)
}
